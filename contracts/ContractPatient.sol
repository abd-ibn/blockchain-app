// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ContractPatient {
    struct Patient {
        string name;
        string dateOfBirth;
        address walletAddress;
        string fileHash;
        string gender;
        string residentialAddress;
        string phoneNumber;
        string email;
    }

    mapping(address => Patient) public patients;
    address[] public patientList;

    event PatientRegistered(address indexed patientAddress, string name, string dateOfBirth);

    function registerPatient(
        string memory _name,
        string memory _dateOfBirth,
        string memory _gender,
        string memory _residentialAddress,
        string memory _phoneNumber,
        string memory _email
    ) public {
        require(patients[msg.sender].walletAddress == address(0), "Patient already registered.");

        patients[msg.sender] = Patient({
            name: _name,
            dateOfBirth: _dateOfBirth,
            walletAddress: msg.sender,
            fileHash: "",
            gender: _gender,
            residentialAddress: _residentialAddress,
            phoneNumber: _phoneNumber,
            email: _email
        });

        patientList.push(msg.sender);
        emit PatientRegistered(msg.sender, _name, _dateOfBirth);
    }

    function getPatient(address _patientAddress) public view returns (Patient memory) {
        return patients[_patientAddress];
    }

    function _updateFileHash(address _patientAddress, string memory _fileHash) external {
        require(patients[_patientAddress].walletAddress != address(0), "Patient not registered.");
        patients[_patientAddress].fileHash = _fileHash;
    }
}
