db = db.getSiblingDB('nebeniac');

db.activations.drop();

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
