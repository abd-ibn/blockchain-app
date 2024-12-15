// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IContractPatient {
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

    function getPatient(address _patientAddress) external view returns (Patient memory);
    function _updateFileHash(address _patientAddress, string memory _fileHash) external;
}

interface IContractAudit {
    function logAction(address doctor, address patient, string memory action, string memory fileHash) external;
}

contract ContractDoctor {
    struct Permission {
        address doctor;
        uint256 grantedAt;
    }

    mapping(address => Permission[]) public permissions;
    mapping(address => mapping(address => bool)) public patientDoctorAccess;

    IContractPatient public patientContract;
    IContractAudit public auditContract;

    event PermissionGranted(address indexed patient, address indexed doctor);
    event PermissionRevoked(address indexed patient, address indexed doctor);
    event FileUploaded(address indexed patient, address indexed doctor, string fileHash);

    constructor(address _patientContractAddress, address _auditContractAddress) {
        patientContract = IContractPatient(_patientContractAddress);
        auditContract = IContractAudit(_auditContractAddress);
    }

    function grantPermission(address _doctor) public {
        require(!patientDoctorAccess[msg.sender][_doctor], "Access already granted.");
        permissions[msg.sender].push(Permission({
            doctor: _doctor,
            grantedAt: block.timestamp
        }));
        patientDoctorAccess[msg.sender][_doctor] = true;
        emit PermissionGranted(msg.sender, _doctor);
    }

    function revokePermission(address _doctor) public {
        require(patientDoctorAccess[msg.sender][_doctor], "No access granted.");
        Permission[] storage patientPermissions = permissions[msg.sender];
        for (uint256 i = 0; i < patientPermissions.length; i++) {
            if (patientPermissions[i].doctor == _doctor) {
                delete patientPermissions[i];
                break;
            }
        }
        patientDoctorAccess[msg.sender][_doctor] = false;
        emit PermissionRevoked(msg.sender, _doctor);
    }

    function checkAccess(address _patient) public view returns (bool) {
        return patientDoctorAccess[_patient][msg.sender];
    }

    function getPatientData(address _patient) public view returns (IContractPatient.Patient memory) {
        require(patientDoctorAccess[_patient][msg.sender], "Access denied.");
        return patientContract.getPatient(_patient);
    }

    function uploadFile(address _patient, string memory _fileHash) public {
        require(patientDoctorAccess[_patient][msg.sender], "You do not have access.");

        patientContract._updateFileHash(_patient, _fileHash);

        auditContract.logAction(msg.sender, _patient, "File Uploaded", _fileHash);

        emit FileUploaded(_patient, msg.sender, _fileHash);
    }
}
