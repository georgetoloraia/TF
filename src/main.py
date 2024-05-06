from headers import *
from libmain import *

# Global state
mapTransactions = {}
cs_mapTransactions = threading.Lock()
nTransactionsUpdated = 0
mapNextTx = {}

mapBlockIndex = {}
hashGenesisBlock = "0x000006b15d1327d67e971d1de9116bd60a3a01556c91b6ebaa416ebc0cfaa646"
pindexGenesisBlock = None
nBestHeight = -1
hashTimeChainBest = 0
pindexBest = None

mapOrphanBlocks = {}
mapOrphanBlocksByPrev = {}

mapWallet = {}
vWalletUpdated = []
cs_mapWallet = threading.Lock()

mapKeys = {}
mapPubKeys = {}
cs_mapKeys = threading.Lock()
keyUser = None

fGenerateBitcoins = 0


'''
MapKey
'''

# Adds a key to the wallet. Returns true if the key is successfully written to the wallet database.
def AddKey(key):
    # Lock the critical section to ensure thread safety when accessing mapKeys
    with cs_mapKeys:
        # Store the private key indexed by the public key in the map
        mapKeys[key.GetPubKey()] = key.GetPrivKey()
        # Store the public key indexed by the hashed public key
        mapPubKeys[hashlib.sha256(key.GetPubKey()).digest()] = key.GetPubKey()
    # Write the public and private key to the wallet database
    return CWalletDB().WriteKey(key.GetPubKey(), key.GetPrivKey())

# Generates a new public key, throws an exception if adding the key fails
def GenerateNewKey():
    key = CKey()
    key.MakeNewKey()  # Generate a new key pair
    if not AddKey(key):  # Attempt to add the generated key to the wallet
        raise RuntimeError("GenerateNewKey() : AddKey failed\n")
    return key.GetPubKey()  # Return the new public key

'''
MapWallet
'''
# Adds a transaction to the wallet. Returns true if the transaction was added or already exists.
def AddToWallet(wtxIn):
    hash = wtxIn.GetHash()  # Get the hash of the transaction
    # Lock the critical section for safe access to mapWallet
    with cs_mapWallet:
        # Try to insert the transaction; only insert if it doesn't already exist
        if hash not in mapWallet:
            mapWallet[hash] = wtxIn
            fInsertedNew = True
        else:
            wtx = mapWallet[hash]  # Reference to the transaction in the wallet
            fInsertedNew = False

            # Debug output
            print("AddToWallet", wtxIn.GetHash(), fInsertedNew)

            # If the transaction was not newly inserted, it might need to be updated
            if wtxIn.hashBlock != 0 and wtxIn.hashBlock != wtx.hashBlock:
                wtx.hashBlock = wtxIn.hashBlock
            if wtxIn.fFromMe and wtxIn.fFromMe != wtx.fFromMe:
                wtx.fFromMe = wtxIn.fFromMe
            if wtxIn.fSpent and wtxIn.fSpent != wtx.fSpent:
                wtx.fSpent = wtxIn.fSpent
            # If no fields were updated, return true as the existing transaction is unchanged
            if not (wtxIn.hashBlock != 0 and wtxIn.hashBlock != wtx.hashBlock
                    or wtxIn.fFromMe and wtxIn.fFromMe != wtx.fFromMe
                    or wtxIn.fSpent and wtxIn.fSpent != wtx.fSpent):
                return True

        # Write the transaction to disk
        if not wtxIn.WriteToDisk():
            return False

        # Notify the UI about the update
        vWalletUpdated.append((hash, fInsertedNew))

    # Repaint the main UI frame to reflect changes
    MainFrameRepaint()
    return True

# Adds a transaction to the wallet if it belongs to this wallet, based on the transaction inputs
def AddToWalletIfMine(tx, pblock):
    if tx.IsMine():  # Check if any of the transaction inputs belong to this wallet
        wtx = CWalletTx(tx)
        if pblock:
            wtx.hashBlock = pblock.GetHash()  # Record the block hash
            wtx.nTime = pblock.nTime          # Record the block timestamp
        else:
            wtx.nTime = GetAdjustedTime()  # Use adjusted time if no block context
        return AddToWallet(wtx)  # Add the transaction to the wallet
    return True

# Reaccepts wallet transactions that are not yet confirmed in a block
def ReacceptWalletTransactions():
    # Lock the critical section to ensure thread safety when accessing mapWallet
    with cs_mapWallet:
        txdb = CTxDB("r")  # Open the transaction database
        # Iterate over all wallet transactions
        for hash, wtx in mapWallet.items():
            # Reaccept transactions that are not in the database
            if not txdb.ContainsTx(hash):
                wtx.AcceptWalletTransaction(txdb, False)

# Rebroadcasts wallet transactions that are not yet confirmed in a block
def RelayWalletTransactions():
    global nLastTime
    if GetTime() - nLastTime < 15 * 60:  # Throttle to run every 15 minutes
        return
    nLastTime = GetTime()  # Update last run time

    # Lock the critical section to ensure thread safety
    with cs_mapWallet:
        txdb = CTxDB("r")  # Open the transaction database
        # Iterate and relay each transaction
        for hash, wtx in mapWallet.items():
            wtx.RelayWalletTransaction(txdb)

'''
CTransactions
'''
# Determines if the transaction input is part of this wallet
def IsMine(self):
    # Search for the transaction in the wallet by its previous output hash
    for txin in self.vin:
        if txin.prevout.hash in mapWallet:
            prev = mapWallet[txin.prevout.hash]
            # Check if the output index is valid and whether the output belongs to this wallet
            if txin.prevout.n < len(prev.vout):
                if prev.vout[txin.prevout.n].IsMine():
                    return True
    return False

# Returns the debit amount of the transaction input if it belongs to this wallet
def GetDebit(self):
    # Search for the transaction in the wallet by its previous output hash
    for txin in self.vin:
        if txin.prevout.hash in mapWallet:
            prev = mapWallet[txin.prevout.hash]
            # Check if the output index is valid and whether the output belongs to this wallet
            if txin.prevout.n < len(prev.vout):
                if prev.vout[txin.prevout.n].IsMine():
                    return prev.vout[txin.prevout.n].nValue  # Return the value of the output
    return 0

# Sets the Merkle branch for the transaction. Returns the depth of the block containing this tx in the main chain
def SetMerkleBranch(self):
    if fClient:  # If running in client mode (light node)
        if self.hashBlock == 0:  # If no block hash, return 0
            return 0
    else:
        # Load the block this transaction is part of
        pos = CTxDB("r").ReadTxPos(self.GetHash())
        if not pos:
            return 0
        block = CBlock()
        if not block.ReadFromDisk(pos.nFile, pos.nBlockPos, True):
            return 0

        self.hashBlock = block.GetHash()  # Update the transaction's block hash

        # Locate the transaction within the block
        for nIndex, tx in enumerate(block.vtx):
            if tx == self:
                break
        else:
            self.vMerkleBranch = []
            nIndex = -1
            print("ERROR: SetMerkleBranch() : couldn't find tx in block")
            return 0

        self.vMerkleBranch = block.GetMerkleBranch(nIndex)  # Store the Merkle branch for the transaction

    # Check if the transaction is in a block that is part of the main chain
    if self.hashBlock not in mapBlockIndex:
        return 0
    pindex = mapBlockIndex[self.hashBlock]
    if not pindex or not pindex.IsInMainChain():
        return 0

    return pindexBest.nHeight - pindex.nHeight + 1  # Return the depth of the block

# Recursively adds supporting transactions to this wallet transaction
def AddSupportingTransactions(self, txdb):
    self.vtxPrev = []

    COPY_DEPTH = 3  # Maximum depth of transactions to copy
    if self.SetMerkleBranch() < COPY_DEPTH:
        vWorkQueue = []  # Queue of transactions to process
        for txin in self.vin:
            vWorkQueue.append(txin.prevout.hash)

        mapWalletPrev = {}  # Previously processed transactions
        setAlreadyDone = set()  # Set of processed transactions to avoid duplication
        for hash in vWorkQueue:
            if hash in setAlreadyDone:
                continue
            setAlreadyDone.add(hash)

            tx = CMerkleTx()
            if hash in mapWallet:
                tx = mapWallet[hash]
                for txWalletPrev in tx.vtxPrev:
                    mapWalletPrev[txWalletPrev.GetHash()] = txWalletPrev
            elif hash in mapWalletPrev:
                tx = mapWalletPrev[hash]
            elif not fClient and txdb.ReadDiskTx(hash, tx):
                pass  # No operation if the transaction is read successfully
            else:
                print("ERROR: AddSupportingTransactions() : unsupported transaction")
                continue

            nDepth = tx.SetMerkleBranch()
            self.vtxPrev.append(tx)

            if nDepth < COPY_DEPTH:
                for txin in tx.vin:
                    vWorkQueue.append(txin.prevout.hash)

    self.vtxPrev.reverse()  # Reverse to maintain the correct order


'''
CBlock And CBlockIndex
'''
def ReadFromDisk(self, pblockindex, fReadTransactions):
    return self.ReadFromDisk(pblockindex.nFile, pblockindex.nBlockPos, fReadTransactions)

def GetBlockValue(nFees):
    nSubsidy = 10000 * CENT
    for i in range(100000, nBestHeight + 1, 100000):
        nSubsidy //= 2
    return nSubsidy + nFees

def GetNextWorkRequired(pindexLast):
    nTargetTimespan = 30 * 24 * 60 * 60
    nTargetSpacing = 15 * 60
    nIntervals = nTargetTimespan // nTargetSpacing

    # Cache
    global pindexLastCache, nBitsCache
    pindexLastCache = None
    nBitsCache = None
    with cs_cache:
        if pindexLast and pindexLast == pindexLastCache:
            return nBitsCache

    # Go back 30 days
    pindexFirst = pindexLast
    for i in range(nIntervals):
        if pindexFirst:
            pindexFirst = pindexFirst.pprev
    if not pindexFirst:
        return MINPROOFOFWORK

    # Load first and last block
    blockFirst = CBlock()
    if not blockFirst.ReadFromDisk(pindexFirst, False):
        raise RuntimeError("GetNextWorkRequired() : blockFirst.ReadFromDisk failed")
    blockLast = CBlock()
    if not blockLast.ReadFromDisk(pindexLast, False):
        raise RuntimeError("GetNextWorkRequired() : blockLast.ReadFromDisk failed")

    # Limit one change per timespan
    nBits = blockLast.nBits
    if blockFirst.nBits == blockLast.nBits:
        nTimespan = blockLast.nTime - blockFirst.nTime
        if nTimespan > nTargetTimespan * 2 and nBits >= MINPROOFOFWORK:
            nBits -= 1
        elif nTimespan < nTargetTimespan / 2:
            nBits += 1

    with cs_cache:
        pindexLastCache = pindexLast
        nBitsCache = nBits
    return nBits

def GetOrphanRoot(pblock):
    # Work back to the first block in the orphan chain
    while pblock.hashPrevBlock in mapOrphanBlocks:
        pblock = mapOrphanBlocks[pblock.hashPrevBlock]
    return pblock.hashPrevBlock

def TestDisconnectBlock(self, txdb, mapTestPool):
    for tx in self.vtx:
        if not tx.TestDisconnectInputs(txdb, mapTestPool):
            return False
    return True

def TestConnectBlock(self, txdb, mapTestPool):
    nFees = 0
    for tx in self.vtx:
        if not tx.TestConnectInputs(txdb, mapTestPool, False, False, nFees):
            return False
    if self.vtx[0].GetValueOut() != GetBlockValue(nFees):
        return False
    return True

def DisconnectBlock(self):
    txdb = CTxDB()
    for tx in self.vtx:
        if not tx.DisconnectInputs(txdb):
            return False
    return True

def ConnectBlock(self, nFile, nBlockPos, nHeight):
    nTxPos = nBlockPos + GetSerializeSize(CBlock(), SER_DISK) - 1 + GetSizeOfCompactSize(len(self.vtx))
    txdb = CTxDB()
    for tx in self.vtx:
        posThisTx = CDiskTxPos(nFile, nBlockPos, nTxPos)
        nTxPos += GetSerializeSize(tx, SER_DISK)
        if not tx.ConnectInputs(txdb, posThisTx, nHeight):
            return False
    txdb.Close()
    for tx in self.vtx:
        AddToWalletIfMine(tx, self)
    return True

def Reorganize(pindexNew, fWriteDisk):
    pfork = pindexBest
    plonger = pindexNew
    while pfork != plonger:
        if not pfork:
            return False
        while plonger.nHeight > pfork.nHeight:
            if not plonger:
                return False
        plonger = plonger.pprev

    vDisconnect = []
    pindex = pindexBest
    while pindex != pfork:
        vDisconnect.append(pindex)
        pindex = pindex.pprev

    vConnect = []
    pindex = pindexNew
    while pindex != pfork:
        vConnect.append(pindex)
        pindex = pindex.pprev
    vConnect.reverse()

    if fWriteDisk:
        txdb = CTxDB("r")
        mapTestPool = {}
        for pindex in vDisconnect:
            if not pindex.TestDisconnectBlock(txdb, mapTestPool):
                return False
        fValid = True
        for pindex in vConnect:
            fValid = fValid and pindex.TestConnectBlock(txdb, mapTestPool)
            if not fValid:
                block = CBlock()
                block.ReadFromDisk(pindex, False)
                pindex.EraseBlockFromDisk()
                mapBlockIndex.pop(block.GetHash(), None)
                del pindex
        if not fValid:
            return False

    for pindex in vDisconnect:
        if fWriteDisk and not pindex.DisconnectBlock():
            return False
        if pindex.pprev:
            pindex.pprev.pnext = None

    for pindex in vConnect:
        if fWriteDisk and not pindex.ConnectBlock():
            return False
        if pindex.pprev:
            pindex.pprev.pnext = pindex

    return True

def AddToBlockIndex(self, nFile, nBlockPos, fWriteDisk):
    hash = self.GetHash()
    pindexNew = CBlockIndex(nFile, nBlockPos)
    if not pindexNew:
        return False
    mapBlockIndex[hash] = pindexNew
    mi = mapBlockIndex.get(hashPrevBlock)
    if mi:
        pindexNew.pprev = mi
        pindexNew.nHeight = pindexNew.pprev.nHeight + 1

    if pindexNew.nHeight > nBestHeight:
        if not pindexGenesisBlock and hash == hashGenesisBlock:
            pindexGenesisBlock = pindexNew
        elif hashPrevBlock == hashTimeChainBest:
            if fWriteDisk:
                if not pindexNew.ConnectBlock():
                    return False
            pindexNew.pprev.pnext = pindexNew
        else:
            if not Reorganize(pindexNew, fWriteDisk):
                return False
        nBestHeight = pindexNew.nHeight
        hashTimeChainBest = hash
        pindexBest = pindexNew
        nTransactionsUpdated += 1
        if fWriteDisk and nTime > GetAdjustedTime() - 30 * 60:
            RelayWalletTransactions()

    MainFrameRepaint()
    return True

def ScanMessageStart(s):
    s.clear(0)
    prevmask = s.exceptions(0)
    p = 0
    try:
        while True:
            c = s.read(1)
            if s.fail():
                s.clear(0)
                s.exceptions(prevmask)
                return False
            if p[p] != c:
                p = 0
            if p[p] == c:
                p += 1
                if p == len(pchMessageStart):
                    s.clear(0)
                    s.exceptions(prevmask)
                    return True
    except:
        s.clear(0)
        s.exceptions(prevmask)
        return False

def OpenBlockFile(nFile, nBlockPos, pszMode):
    if nFile == -1:
        return None
    file = open(f"blk{nFile:04d}.dat", pszMode)
    if not file:
        return None
    if nBlockPos != 0 and 'a' not in pszMode and 'w' not in pszMode:
        if fseek(file, nBlockPos, SEEK_SET) != 0:
            file.close()
            return None
    return file

nCurrentBlockFile = 1

def AppendBlockFile(nFileRet):
    nFileRet = 0
    while True:
        file = OpenBlockFile(nCurrentBlockFile, 0, "ab")
        if not file:
            return None
        if fseek(file, 0, SEEK_END) != 0:
            return None
        if ftell(file) < 0x7F000000 - MAX_SIZE:
            nFileRet = nCurrentBlockFile
            return file
        file.close()
        nCurrentBlockFile += 1

def LoadBlockIndex(fAllowNew):
    global nCurrentBlockFile
    nCurrentBlockFile = 1

    while True:
        filein = OpenBlockFile(nCurrentBlockFile, 0, "rb")
        if not filein:
            if nCurrentBlockFile > 1:
                nCurrentBlockFile -= 1
                break
            if not fAllowNew:
                return False
            # Genesis block
            txNew = CTransaction()
            txNew.vin.resize(1)
            txNew.vout.resize(1)
            txNew.vin[0].scriptSig = CScript() << 247422313
            txNew.vout[0].nValue = 10000
            txNew.vout[0].scriptPubKey = CScript() << OP_CODESEPARATOR << CBigNum("0x31D18A083F381B4BDE37B649AACF8CD0AFD88C53A3587ECDB7FAF23D449C800AF1CE516199390BFE42991F10E7F5340F2A63449F0B639A7115C667E5D7B051D404") << OP_CHECKSIG
            block = CBlock()
            block.vtx.push_back(txNew)
            block.hashPrevBlock = 0
            block.hashMerkleRoot = block.BuildMerkleTree()
            block.nTime = 1221069728
            block.nBits = 20
            block.nNonce = 141755
            assert(block.GetHash() == hashGenesisBlock)
            # Start new block file
            nFile, nBlockPos = 0, 0
            if not block.WriteToDisk(True, nFile, nBlockPos):
                return False
            if not block.AddToBlockIndex(nFile, nBlockPos, True):
                return False
            break

        nFilesize = GetFilesize(filein)
        if nFilesize == -1:
            return False
        filein.nType |= SER_BLOCKHEADERONLY

        while ScanMessageStart(filein):
            nSize = 0
            filein >> nSize
            if nSize > MAX_SIZE or ftell(filein) + nSize > nFilesize:
                continue
            nBlockPos = ftell(filein)
            block = CBlock()
            filein >> block
            if fseek(filein, nBlockPos + nSize, SEEK_SET) != 0:
                break
            if not block.AddToBlockIndex(nCurrentBlockFile, nBlockPos, False):
                return False
    return True

def PrintTimechain():
    mapNext = defaultdict(list)
    for mi in mapBlockIndex:
        pindex = mapBlockIndex[mi]
        mapNext[pindex.pprev].append(pindex)

    vStack = [(0, pindexGenesisBlock)]
    nPrevCol = 0

    while vStack:
        nCol, pindex = vStack.pop()

        if nCol > nPrevCol:
            for i in range(nCol-1):
                print("| ", end="")
            print("|\\")
        elif nCol < nPrevCol:
            for i in range(nCol):
                print("| ", end="")
            print("|")

        nPrevCol = nCol

        for i in range(nCol):
            print("| ", end="")

        print(f"{pindex.nHeight} ({pindex.nFile},{pindex.nBlockPos})")

        vNext = mapNext[pindex]
        for i in range(len(vNext)):
            if vNext[i].pnext:
                vNext[0], vNext[i] = vNext[i], vNext[0]
                break

        for i in range(len(vNext)):
            vStack.append((nCol+i, vNext[i]))


def CheckBlock(self):
    if not self.vtx or len(self.vtx) > MAX_SIZE or GetSerializeSize(self, SER_DISK) > MAX_SIZE:
        return error("CheckBlock() : size limits failed")

    if self.nTime > GetAdjustedTime() + 36 * 60 * 60:
        return error("CheckBlock() : block timestamp out of range")

    if self.nBits < MINPROOFOFWORK:
        return error("CheckBlock() : nBits below minimum")
    if self.GetHash() > (~uint256(0) >> self.nBits):
        return error("CheckBlock() : hash doesn't match nBits")

    if not self.vtx or not self.vtx[0].IsCoinBase():
        return error("CheckBlock() : first tx is not coinbase")
    for i in range(1, len(self.vtx)):
        if self.vtx[i].IsCoinBase():
            return error("CheckBlock() : more than one coinbase")

    for tx in self.vtx:
        if not tx.CheckTransaction():
            return error("CheckBlock() : CheckTransaction failed")

    if self.hashMerkleRoot != self.BuildMerkleTree():
        return error("CheckBlock() : hashMerkleRoot mismatch")

    return True


def AcceptBlock(self):
    hash = self.GetHash()
    if hash in mapBlockIndex:
        return False

    mi = mapBlockIndex.get(self.hashPrevBlock)
    if not mi:
        return False
    pindexPrev = mi

    blockPrev = CBlock()
    if not blockPrev.ReadFromDisk(pindexPrev, False):
        return False
    if self.nTime <= blockPrev.nTime:
        return False

    if self.nBits != GetNextWorkRequired(pindexPrev):
        return False

    with CTxDB("r") as txdb:
        mapTestPool = {}
        fIgnoreDiskConflicts = self.hashPrevBlock != hashTimeChainBest
        nFees = 0
        for tx in self.vtx:
            if not tx.TestConnectInputs(txdb, mapTestPool, False, fIgnoreDiskConflicts, nFees):
                return error("AcceptBlock() : TestConnectInputs failed")
        if self.vtx[0].GetValueOut() != GetBlockValue(nFees):
            return False

    nFile, nBlockPos = 0, 0
    if not self.WriteToDisk(not fClient, nFile, nBlockPos):
        return False
    if not self.AddToBlockIndex(nFile, nBlockPos, True):
        return False

    if hashTimeChainBest == hash:
        RelayInventory(CInv(MSG_BLOCK, hash))

    vchPubKey = []
    if ExtractPubKey(self.vtx[0].vout[0].scriptPubKey, False, vchPubKey):
        nRand = 0
        RAND_bytes(nRand, sizeof(nRand))
        nAtom = nRand % (USHRT_MAX - 100) + 100
        vAtoms = [nAtom]
        AddAtomsAndPropagate(Hash(vchPubKey), vAtoms, True)

    return True


def ProcessBlock(pfrom, pblock):
    hash = pblock.GetHash()
    if hash in mapBlockIndex or hash in mapOrphanBlocks:
        return False

    if not pblock.CheckBlock():
        print("CheckBlock FAILED")
        del pblock
        return False

    if hashPrevBlock not in mapBlockIndex:
        mapOrphanBlocks[hash] = pblock
        mapOrphanBlocksByPrev[hashPrevBlock] = pblock
        if pfrom:
            pfrom.PushMessage("getblocks", CBlockLocator(pindexBest), GetOrphanRoot(pblock))
        return True

    if not pblock.AcceptBlock():
        print("AcceptBlock FAILED")
        del pblock
        return False

    del pblock

    for mi in mapOrphanBlocksByPrev:
        if mi[1] == hash:
            pblockOrphan = mi[0]
            pblockOrphan.AcceptBlock()
            mapOrphanBlocks.erase(pblockOrphan.GetHash())
            del pblockOrphan
    mapOrphanBlocksByPrev.erase(hash)

    return True
