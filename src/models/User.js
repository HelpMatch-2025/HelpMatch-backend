import { Schema, model, Types } from 'mongoose'

const schema = new Schema({
  password: { type: String, required: true },
  userName: { type: String, required: true, unique: true },
  securityQuestions: {
    question1: { type: String, required: true },
    answer1: { type: String, required: true, minlength: 3 },
    question2: { type: String, required: true },
    answer2: { type: String, required: true, minlength: 3 },
    question3: { type: String, required: true },
    answer3: { type: String, required: true, minlength: 3 },
  },
  iv: { type: String, required: true },
  encryptedPrivateKeyPart: { type: String, required: true },
  referredBy: { type: Types.ObjectId, ref: 'User' },
  avatarUrl: { type: String, default: '' },
})

const User = model('User', schema)

export default User
