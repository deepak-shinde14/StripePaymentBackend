const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  paymentIntentId: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'usd' },
  status: { type: String, default: 'succeeded' },
  description: String,
  metadata: Object,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Transaction', transactionSchema);