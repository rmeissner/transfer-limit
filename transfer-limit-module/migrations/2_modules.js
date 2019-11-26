const TransferLimitModule = artifacts.require("TransferLimitModule");
const AllowanceModule = artifacts.require("AllowanceModule");

module.exports = function(deployer) {
  deployer.deploy(AllowanceModule);
  //deployer.deploy(TransferLimitModule);
};
