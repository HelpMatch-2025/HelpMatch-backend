import cloudinary from '../utils/cloudinary.js';

const uploadAvatar = async (req, res, next) => {
  try {
    const { avatar } = req.body;
    if (!avatar) return next();

    let avatarUrl = avatar;
    if (avatar.startsWith('data:image/')) {
      const result = await cloudinary.uploader.upload(avatar, {
        folder: 'avatars',
      });
      avatarUrl = result.secure_url;
    }
    req.body.avatarUrl = avatarUrl;
    next();
  } catch (error) {
    console.error('Avatar upload error:', error);
    res.status(500).json({
      message: 'Avatar upload failed',
      error: error.message,
    });
  }
};

export default uploadAvatar;
