import { Router } from 'express';
import authMiddleware from '../middleware/auth.js';
import ChatRoom from '../models/ChatRoom.js';
import Message from '../models/Message.js';
import User from '../models/User.js';
import Products from '../models/Products.js';

const chatRouter = Router();
chatRouter.use(authMiddleware);

chatRouter.post('/rooms', async (req, res) => {
  try {
    const userId = req.user.id;
    const { productId } = req.body;
    const product = await Products.findById(productId);
    if (!product) return res.status(404).json({ message: 'Product not found' });
    if (product.userId.toString() === userId) {
      return res.status(400).json({ message: "You can't chat with yourself" });
    }

    const participants = [userId, product.userId.toString()];
    let room = await ChatRoom.findOne({ productId, participants: { $all: participants } });
    if (!room) {
      room = await ChatRoom.create({ productId, participants });
    }

    res.status(201).json({
      roomId: room._id.toString(),
      productId: room.productId.toString(),
      participants: room.participants.map(id => id.toString())
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

chatRouter.get('/rooms', async (req, res) => {
  try {
    const userId = req.user.id;
    const rooms = await ChatRoom.find({ participants: userId }).lean();
    const result = await Promise.all(
      rooms.map(async r => {
        const product = await Products.findById(r.productId).select('name').lean();
        const other = r.participants.find(p => p.toString() !== userId);
        const user = await User.findById(other).select('userName').lean();
        const unreadCount = await Message.countDocuments({ chatRoomId: r._id, readBy: { $ne: userId } });
        return {
          roomId: r._id.toString(),
          productId: r.productId.toString(),
          participants: r.participants.map(id => id.toString()),
          chatName: `${user.userName}: ${product?.name || ''}`,
          unreadCount
        };
      })
    );
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

chatRouter.get('/rooms/:roomId/messages', async (req, res) => {
  try {
    const { roomId } = req.params;
    const limit = parseInt(req.query.limit, 10) || 50;
    const offset = parseInt(req.query.offset, 10) || 0;
    const msgs = await Message.find({ chatRoomId: roomId })
      .sort({ createdAt: -1 })
      .skip(offset)
      .limit(limit)
      .populate('senderId', 'userName')
      .lean();
    res.json(msgs.reverse());
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

chatRouter.get('/rooms/:roomId/participants', async (req, res) => {
  try {
    const { roomId } = req.params;
    const room = await ChatRoom.findById(roomId).select('participants').lean();
    const users = await User.find({ _id: { $in: room.participants } })
      .select('userName')
      .lean();
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

chatRouter.get('/rooms/:roomId/unread-count', async (req, res) => {
  try {
    const { roomId } = req.params;
    const userId = req.user.id;
    const count = await Message.countDocuments({ chatRoomId: roomId, readBy: { $ne: userId } });
    res.json({ count });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

export default chatRouter;
