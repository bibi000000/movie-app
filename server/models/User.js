const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const saltRounds = 10
const jwt = require('jsonwebtoken')

const userSchema = mongoose.Schema({
  name: {
    type: String,
    maxlength: 50
  },
  email: {
    type: String,
    trim: true,
    unique: 1
  },
  password: {
    type: String,
    minlength: 5
  },
  lastname: {
    type: String,
    maxlength: 50
  },
  role: {
    type: Number,
    default: 0
  },
  image: String,
  token: {  // token을 이용해서 나중에 유효성 같은 거 관리
    type: String
  },
  tokenExp: { // token 사용할 수 있는 유효 기간
    type: Number
  }
})

//pre()는 mongoose에서 가져온 메서드
userSchema.pre('save', function (next) {
  let user = this;  //this는 userSchema를 가리킴
  //모델안의 field 중에 password가 변환될 때만 bcrypt를 이용해서 비밀번호를 암호화해준다
  if (user.isModified('password')) {
    //비밀번호를 암호화시킨다.
    bcrypt.genSalt(saltRounds, function (err, salt) {
      if (err) return next(err)
      bcrypt.hash(user.password, salt, function (err, hash) {
        //hash는 암호화된 비밀번호
        if (err) return next(err)
        user.password = hash
        next()
      })
    })
  } else {
    next()
  }
})

userSchema.methods.comparePassword = function (plainPassword, callback) {
  //plainPassword abcabc    암호화된 비밀번호 $~
  bcrypt.compare(plainPassword, this.password, function (err, isMatch) {
    if (err) return callback(err)
    callback(null, isMatch)
  })
}

userSchema.methods.generateToken = function (callback) {
  let user = this;
  //jsonwebtoken을 이용해서 token을 생성하기
  let token = jwt.sign(user._id.toHexString(), 'secretToken')
  user.token = token
  user.save(function (err, user) {
    if (err) return callback(err)
    callback(null, user)
  })
}

userSchema.statics.findByToken = function (token, callback) {
  let user = this;

  //토큰을 decode 한다.
  jwt.verify(token, 'secretToken', function (err, decoded) {
    //유저아이디를 이용해서 유저를 찾은 다음에 클라이언트에서 가져온 token과 db에 보관된 토큰이 일치하는지 확인
    user.findOne({ "_id": decoded, "token": token }, function (err, user) {
      if (err) return callback(err)
      callback(null, user)
    })
  })
}

// schema를 model로 감싸준다
const User = mongoose.model('User', userSchema) // 모델의 이름, 스키마

module.exports = { User }