import cloudinary from '../utils/cloudinary.js';

const uploadImagesMiddleware = async (req, res, next) => {
  try {
    let { images } = req.body;

    if (!Array.isArray(images) || images.length === 0) {
      return res.status(400).json({ message: 'Images must be a non-empty array' });
    }

    const uploadedUrls = [];

    for (const base64 of images) {
      const result = await cloudinary.uploader.upload(base64, {
        folder: 'products',
      });
      uploadedUrls.push(result.secure_url);
    }

    req.body.images = uploadedUrls;
    next();
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ message: 'Image upload failed', error: error.message });
  }
};

export default uploadImagesMiddleware;
