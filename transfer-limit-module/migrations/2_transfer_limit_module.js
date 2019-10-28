const TransferLimitModule = artifacts.require("TransferLimitModule");

module.exports = function(deployer) {
  deployer.deploy(TransferLimitModule);
};
