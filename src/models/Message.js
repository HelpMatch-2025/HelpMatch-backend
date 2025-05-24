import { Schema, model, Types } from 'mongoose';

const messageSchema = new Schema(
  {
    chatRoomId: { type: Types.ObjectId, ref: 'ChatRoom', required: true },
    senderId:    { type: Types.ObjectId, ref: 'User',     required: true },
    content:     { type: String,       required: true },
    readBy:      [{ type: Types.ObjectId, ref: 'User' }]
  },
  { timestamps: { createdAt: 'createdAt' } }
);

export default model('Message', messageSchema);
