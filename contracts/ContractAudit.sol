// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ContractAudit {
    struct AuditEntry {
        address doctor;
        address patient;
        string action;
        string fileHash;
        uint256 timestamp;
    }

    AuditEntry[] public auditTrail;
    mapping(address => AuditEntry[]) public patientAuditTrail;

    event ActionLogged(address indexed doctor, address indexed patient, string action, string fileHash, uint256 timestamp);

    // Log an action
    function logAction(address _doctor, address _patient, string memory _action, string memory _fileHash) public {
        AuditEntry memory entry = AuditEntry({
            doctor: _doctor,
            patient: _patient,
            action: _action,
            fileHash: _fileHash,
            timestamp: block.timestamp
        });

        auditTrail.push(entry); // Add to global audit
        patientAuditTrail[_patient].push(entry); // Add to patient specific audit

        emit ActionLogged(_doctor, _patient, _action, _fileHash, block.timestamp);
    }

    // Retrieve audit for a specific patient
    function getPatientAuditTrail(address _patient) public view returns (AuditEntry[] memory) {
        return patientAuditTrail[_patient];
    }
}
