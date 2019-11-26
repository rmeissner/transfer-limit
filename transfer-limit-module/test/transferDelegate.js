const utils = require('@gnosis.pm/safe-contracts/test/utils/general')
const { wait, waitUntilBlock } = require('./utils')(web3);

const GnosisSafe = artifacts.require("./GnosisSafe.sol")
const TransferLimitModule = artifacts.require("./TransferLimitModule.sol")
const TestToken = artifacts.require("./TestToken.sol")

contract('TransferLimitModule delegate', function(accounts) {
    let lw
    let gnosisSafe
    let safeModule

    const CALL = 0
    const ADDRESS_0 = "0x0000000000000000000000000000000000000000"

    beforeEach(async function() {
        // Create lightwallet
        lw = await utils.createLightwallet()

        // Create Master Copies
        gnosisSafe = await GnosisSafe.new()
        safeModule = await TransferLimitModule.new()
        await gnosisSafe.setup([lw.accounts[0], lw.accounts[1], accounts[1]], 2, ADDRESS_0, "0x", ADDRESS_0, ADDRESS_0, 0, ADDRESS_0)
    })

    let execTransaction = async function(to, value, data, operation, message) {
        let nonce = await gnosisSafe.nonce()
        let transactionHash = await gnosisSafe.getTransactionHash(to, value, data, operation, 0, 0, 0, ADDRESS_0, ADDRESS_0, nonce)
        let sigs = utils.signTransaction(lw, [lw.accounts[0], lw.accounts[1]], transactionHash)
        utils.logGasUsage(
            'execTransaction ' + message,
            await gnosisSafe.execTransaction(to, value, data, operation, 0, 0, 0, ADDRESS_0, ADDRESS_0, sigs)
        )
    }

    it('Execute transfer limit with delegate', async () => {
        const token = await TestToken.new({from: accounts[0]})
        await token.transfer(gnosisSafe.address, 1000, {from: accounts[0]}) 
        //const mintToken = await TestCompound.new(sourceToken.address)
        
        let enableModuleData = await gnosisSafe.contract.methods.enableModule(safeModule.address).encodeABI()
        await execTransaction(gnosisSafe.address, 0, enableModuleData, CALL, "enable module")
        let modules = await gnosisSafe.getModules()
        assert.equal(1, modules.length)
        assert.equal(safeModule.address, modules[0])

        let setLimitData = await safeModule.contract.methods.setLimit(token.address, 100, 60 * 24).encodeABI()
        await execTransaction(safeModule.address, 0, setLimitData, CALL, "set limit")

        let tokens = await safeModule.getTokens(gnosisSafe.address)
        assert.equal(1, tokens.length)
        assert.equal(token.address, tokens[0])
        let tokenLimit = await safeModule.getTokenLimit(gnosisSafe.address, token.address)
        assert.equal(100, tokenLimit[0])
        assert.equal(0, tokenLimit[1])
        assert.equal(24 * 60, tokenLimit[2])
        assert.equal(0, tokenLimit[3])
        assert.equal(0, tokenLimit[4])

        let addDelegateData = await safeModule.contract.methods.addDelegate(lw.accounts[4]).encodeABI()
        await execTransaction(safeModule.address, 0, addDelegateData, CALL, "add delegate")

        let delegates = await safeModule.getDelegates(gnosisSafe.address, 0, 10)
        assert.equal(1, delegates.results.length)
        assert.equal(lw.accounts[4], delegates.results[0].toLowerCase())

        assert.equal(1000, await token.balanceOf(gnosisSafe.address))
        assert.equal(0, await token.balanceOf(accounts[1]))

        let nonce = tokenLimit[4]
        let transferLimitHash = await safeModule.generateTransferHash(
            gnosisSafe.address, token.address, accounts[1], 60, ADDRESS_0, 0, nonce
        )
        let signature = utils.signTransaction(lw, [lw.accounts[4]], transferLimitHash)

        utils.logGasUsage(
            'executeLimitTransfer',
            await safeModule.executeLimitTransfer(
                gnosisSafe.address, token.address, accounts[1], 60, ADDRESS_0, 0, signature
            )
        )

        assert.equal(940, await token.balanceOf(gnosisSafe.address))
        assert.equal(60, await token.balanceOf(accounts[1]))

        tokenLimit = await safeModule.getTokenLimit(gnosisSafe.address, token.address)
        assert.equal(100, tokenLimit[0])
        assert.equal(60, tokenLimit[1])
        assert.equal(24 * 60, tokenLimit[2])
        assert.ok(tokenLimit[3] > 0)
        assert.equal(1, tokenLimit[4])
    })
})