import { Schema, model, Types } from 'mongoose';

const chatRoomSchema = new Schema(
  {
    productId: { type: Types.ObjectId, ref: 'Products', required: true },
    participants: {
      type: [{ type: Types.ObjectId, ref: 'User', required: true }],
      validate: { validator: arr => arr.length === 2, message: 'Must have exactly two participants' }
    }
  },
  { timestamps: true }
);

chatRoomSchema.index({ productId: 1, participants: 1 });
chatRoomSchema.pre('save', function(next) { this.participants.sort(); next(); });

export default model('ChatRoom', chatRoomSchema);