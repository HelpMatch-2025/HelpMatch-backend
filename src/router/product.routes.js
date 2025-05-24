import { Router } from 'express';
import Products from '../models/Products.js';
import { check, validationResult } from 'express-validator';
import uploadImagesMiddleware from '../middleware/uploadImagesMiddleware.js';
import processUpdatedImages from '../middleware/processUpdatedImages.js';
import authMiddleware from '../middleware/auth.js';

const productRouter = Router();

productRouter.use(authMiddleware);

productRouter.post(
  '/create',
  [
    check('name', 'Name is required').notEmpty(),
    check('description', 'Description is required').notEmpty(),
    check('category', 'Category is required').notEmpty(),
    check('images', 'Images must be an array').isArray(),
    check('purpose', 'Purpose is required and must be either "needs" or "proposals"')
      .isIn(['needs', 'proposals']),
    uploadImagesMiddleware,
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array(), message: 'Invalid data' })
      }

      const { name, description, category, images, purpose } = req.body;
      const userId = req.user.id; 

      const newCard = new Products({
        userId,
        name,
        description,
        category,
        images,
        purpose,
      });

      await newCard.save();

      res.status(201).json({ message: 'Product card created', card: newCard });
    } catch (err) {
      console.error('Create product card error:', err);
      res.status(500).json({ message: 'Server error', error: err.message });
    }
  }
);

productRouter.get('/', async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '', category, purpose } = req.query;

    const currentPage = parseInt(page);
    const perPage = parseInt(limit);

    const filter = {};

    if (search) {
      filter.name = { $regex: search, $options: 'i' };
    }

    if (category) {
      filter.category = category;
    }

    if (purpose) {
      filter.purpose = purpose;
    }

    const total = await Products.countDocuments(filter);
    const totalPages = Math.ceil(total / perPage);

    const cards = await Products.find(filter)
      .skip((currentPage - 1) * perPage)
      .limit(perPage);

    res.json({
      cards,
      pagination: {
        totalItems: total,
        perPage,
        currentPage,
        totalPages,
        remainingItems: total - currentPage * perPage > 0
          ? total - currentPage * perPage
          : 0
      }
    });
  } catch (err) {
    console.error('Get all product cards error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

productRouter.put(
  '/:id',
  [
    check('name', 'Name is required').optional().notEmpty(),
    check('description', 'Description is required').optional().notEmpty(),
    check('images', 'Images must be an array').optional().isArray(),
    processUpdatedImages,
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array(), message: 'Invalid data' })
      }

      const { id } = req.params
      const updatedFields = req.body

      const updatedCard = await Products.findByIdAndUpdate(id, updatedFields, { new: true })

      if (!updatedCard) {
        return res.status(404).json({ message: 'Product card not found' })
      }

      res.json({ message: 'Product card updated', card: updatedCard })
    } catch (err) {
      console.error('Update product card error:', err)
      res.status(500).json({ message: 'Server error', error: err.message })
    }
  }
)

productRouter.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params

    const deletedCard = await Products.findByIdAndDelete(id)

    if (!deletedCard) {
      return res.status(404).json({ message: 'Product card not found' })
    }

    res.json({ message: 'Product card deleted', card: deletedCard })
  } catch (err) {
    console.error('Delete product card error:', err)
    res.status(500).json({ message: 'Server error', error: err.message })
  }
})

productRouter.get('/task/:taskId', async (req, res) => {
  try {
    const { taskId } = req.params
    const task = await Products.findById(taskId)

    if (!task) {
      return res.status(404).json({ message: 'Task not found' })
    }

    res.json({ task })
  } catch (err) {
    console.error('Get task by ID error:', err)
    res.status(500).json({ message: 'Server error', error: err.message })
  }
})

productRouter.get('/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    let { page = 1, limit = 10, search = '', category, purpose } = req.query;

    const currentPage = parseInt(page, 10);
    const perPage = parseInt(limit, 10);

    const filter = { userId };

    if (search) {
      filter.name = { $regex: search, $options: 'i' };
    }
    if (category) {
      filter.category = category;
    }
    if (purpose) {
      filter.purpose = purpose;
    }

    const totalItems = await Products.countDocuments(filter);
    const totalPages = Math.ceil(totalItems / perPage);

    const tasks = await Products.find(filter)
      .skip((currentPage - 1) * perPage)
      .limit(perPage);

    res.json({
      tasks,
      pagination: {
        totalItems,
        perPage,
        currentPage,
        totalPages,
        remainingItems:
          totalItems - currentPage * perPage > 0
            ? totalItems - currentPage * perPage
            : 0,
      },
    });
  } catch (err) {
    console.error('Get user products error:', err);
    res
      .status(500)
      .json({ message: 'Server error', error: err.message });
  }
});

productRouter.get('/user/:userId/task/:taskId', async (req, res) => {
  try {
    const { userId, taskId } = req.params
    const task = await Products.findOne({ _id: taskId, userId })

    if (!task) {
      return res.status(404).json({ message: 'Task not found for this user' })
    }

    res.json({ task })
  } catch (err) {
    console.error('Get user-specific task error:', err)
    res.status(500).json({ message: 'Server error', error: err.message })
  }
})

export default productRouter
