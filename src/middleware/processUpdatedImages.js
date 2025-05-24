import cloudinary from '../utils/cloudinary.js';

const processUpdatedImages = async (req, res, next) => {
  try {
    const { images } = req.body;

    if (!images || !Array.isArray(images)) return next();

    const finalUrls = [];

    for (const image of images) {
      if (image.startsWith('data:image/')) {
        const result = await cloudinary.uploader.upload(image, {
          folder: 'products',
        });
        finalUrls.push(result.secure_url);
      } else {
        finalUrls.push(image);
      }
    }

    req.body.images = finalUrls;
    next();
  } catch (error) {
    console.error('Image processing failed:', error);
    res.status(500).json({ message: 'Image processing failed', error: error.message });
  }
};

export default processUpdatedImages;
