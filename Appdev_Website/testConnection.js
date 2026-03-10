const mongoose = require('mongoose');

mongoose.connect("mongodb+srv://lancemacalalad1104_db_user:OxUBj8xxF85JYKIA@cluster0.9zcnyng.mongodb.net/Users?retryWrites=true&w=majority&tls=true", {
  tlsAllowInvalidCertificates: true,
})
.then(() => {
  console.log("✅ Connected successfully!");
  process.exit(0);
})
.catch((err) => {
  console.error("❌ Connection failed:", err);
  process.exit(1);
});
