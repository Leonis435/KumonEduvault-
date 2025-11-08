const mongoose = require('mongoose');

const threatSchema = new mongoose.Schema({
  fileName: { type: String, required: true },
  uploaderEmail: { type: String, required: true },
  detectedViruses: [{ type: String }],
  detectedAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['blocked', 'resolved', 'ignored'], default: 'blocked' }
});

module.exports = mongoose.model('Threat', threatSchema);
