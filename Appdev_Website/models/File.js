const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  fileName: { type: String, required: true },
  worksheetValue: { type: String, required: true },
  data: { type: Buffer, required: true },
  contentType: { type: String, required: true },
  uploaderEmail: { type: String, required: true },
  instructor: { type: mongoose.Schema.Types.ObjectId, ref: 'Instructor', required: true },
  uploadedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('File', fileSchema);
