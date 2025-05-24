
import mongoose from 'mongoose';

const referralSchema = new mongoose.Schema({
  code: {
    type: String,
    unique: true,
    required: true
  },
  inviter: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 }  
  },
  used: {
    type: Boolean,
    default: false
  }
});


const Referral = mongoose.model('Referral', referralSchema)

export default Referral;
