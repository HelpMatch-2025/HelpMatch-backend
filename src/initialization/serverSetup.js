import http from 'http';
import jwt from 'jsonwebtoken';
import express from 'express';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import DBstart from './database.js';
import router from '../router/routes.js';
import Message from '../models/Message.js';

dotenv.config();
const PORT = process.env.SERVER_PORT;

const serverSetup = async (app) => {
  await DBstart();

  app.use(express.json({ limit: '200mb' }));
  app.use(express.urlencoded({ extended: true, limit: '200mb' }));
  app.use('/api', router);

  const httpServer = http.createServer(app);
  const io = new Server(httpServer, {
    cors: { origin: process.env.CLIENT_URL || '*', methods: ['GET','POST'] }
  });

  io.use((socket, next) => {
    const token = socket.handshake.auth?.token?.split(' ')[1];
    if (!token) return next(new Error('Auth error'));
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = payload.userId;
      return next();
    } catch {
      return next(new Error('Auth error'));
    }
  });

  io.on('connection', (socket) => {
    console.log(`User ${socket.userId} connected, socket ${socket.id}`);

    socket.on('join_room', (roomId) => {
      socket.join(roomId);
      io.to(roomId).emit('online_users', {
        roomId,
        users: Array.from(io.sockets.adapter.rooms.get(roomId) || [])
      });
    });

    socket.on('leave_room', (roomId) => {
      socket.leave(roomId);
      io.to(roomId).emit('online_users', {
        roomId,
        users: Array.from(io.sockets.adapter.rooms.get(roomId) || [])
      });
    });

    socket.on('send_message', async ({ roomId, content }) => {
      try {
        const msg = await Message.create({
          chatRoomId: roomId,
          senderId: socket.userId,
          content
        });
        await msg.populate('senderId', 'userName');
        io.to(roomId).emit('new_message', msg);
      } catch (err) {
        console.error('Message save error:', err);
      }
    });

    socket.on('message_read', async ({ messageId, roomId }) => {
      try {
        const msg = await Message.findById(messageId);
        if (!msg) return;
        if (!msg.readBy.includes(socket.userId)) {
          msg.readBy.push(socket.userId);
          await msg.save();
        }
        io.to(roomId).emit('message_read', { messageId, userId: socket.userId });
      } catch (err) {
        console.error('Message read error:', err);
      }
    });

    socket.on('disconnecting', () => {
      for (const roomId of socket.rooms) {
        if (roomId === socket.id) continue;
        io.to(roomId).emit('online_users', {
          roomId,
          users: Array.from(io.sockets.adapter.rooms.get(roomId) || [])
        });
      }
    });
  });

  return httpServer.listen(PORT, () =>
    console.log(`Server started on port ${PORT}`)
  );
};

export default serverSetup;
