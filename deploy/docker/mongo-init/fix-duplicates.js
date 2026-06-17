// Fix for duplicate activations - create unique compound index
db = db.getSiblingDB('nebeniac');

// Drop existing activations with duplicates
db.activations.drop();

// Create unique compound index for licenseKey + hardwareFingerprint
db.activations.createIndex(
  { 
    "licenseKey": 1, 
    "hardwareFingerprint": 1 
  }, 
  { 
    unique: true,
    name: "unique_license_hardware"
  }
);

print("Created unique compound index on activations collection");
print("Index prevents duplicate activations for same license+hardware combination");
