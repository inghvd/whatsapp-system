const mongoose = require('mongoose');

const contactSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  phone: String,
  name: String
});

contactSchema.index({ userId: 1, phone: 1 }, { unique: true });

module.exports = mongoose.model('Contact', contactSchema);

