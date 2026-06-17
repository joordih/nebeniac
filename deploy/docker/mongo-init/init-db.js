db = db.getSiblingDB('nebeniac');
db.createUser({
    user: 'nebeniac_app',
    pwd: 'nebeniac_app_password',
    roles: [
        {
            role: 'readWrite',
            db: 'nebeniac'
        }
    ]
});
db.createCollection('users');
db.createCollection('licenses');
db.createCollection('plugins');
db.createCollection('activations');
db.createCollection('sessions');
db.createCollection('userSessions');
db.createCollection('auditLogs');
db.users.createIndex({"email": 1}, {unique: true});
db.users.createIndex({"username": 1}, {sparse: true});
db.users.createIndex({"emailVerificationToken": 1}, {sparse: true});
db.users.createIndex({"passwordResetToken": 1}, {sparse: true});

db.licenses.createIndex({"licenseKey": 1}, {unique: true});
db.licenses.createIndex({"customerEmail": 1});
db.licenses.createIndex({"active": 1});
db.licenses.createIndex({"expiresAt": 1});

db.plugins.createIndex({"pluginId": 1}, {unique: true});
db.plugins.createIndex({"active": 1});
db.plugins.createIndex({"ownerId": 1});

db.activations.createIndex({"licenseKey": 1});
db.activations.createIndex({"hardwareFingerprint": 1});
db.activations.createIndex({"active": 1});

db.sessions.createIndex({"sessionToken": 1}, {unique: true});
db.sessions.createIndex({"licenseKey": 1});
db.sessions.createIndex({"expiresAt": 1});

db.userSessions.createIndex({"token": 1}, {unique: true});
db.userSessions.createIndex({"userId": 1});
db.userSessions.createIndex({"expiresAt": 1});

db.auditLogs.createIndex({"timestamp": 1});
db.auditLogs.createIndex({"event": 1});
db.auditLogs.createIndex({"licenseKey": 1});
db.users.insertOne({
    _id: ObjectId(),
    id: "admin-001",
    email: "admin@nebeniac.com",
    username: "admin",
    firstName: "Administrador",
    lastName: "Sistema",
    passwordHash: "wPGVL60xE3mzhWPhMXaqYimY9gqee/6dS9+pt+zsowvRJfdWtVqOAINZtuVBOuj6tgwNAeMCsqCAQ6x2SQ7IKA==",
    role: "ADMIN",
    active: true,
    emailVerified: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    permissions: ["ALL"]
});
db.plugins.insertOne({
    _id: ObjectId(),
    pluginId: "example-plugin",
    name: "Example Plugin",
    version: "1.0.0",
    description: "Example plugin demonstrating the protection system",
    originalMainClass: "com.example.ExamplePlugin",
    encryptionKey: "example_key_base64",
    ownerId: "admin-001",
    active: true,
    createdAt: new Date(),
    updatedAt: new Date()
});

print("Database initialized successfully");
print("Admin user created: admin@nebeniac.com");
print("Example plugin created: example-plugin");
