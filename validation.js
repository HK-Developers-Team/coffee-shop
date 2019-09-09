const Joi = require('@hapi/joi')

const registerValidation = (data) => {
    const scheme = {
        username: Joi.string().min(6).required(),
        password: Joi.string().min(6).required(),
        email: Joi.string().min(6).required().email(),
    };
    return Joi.validate(data, scheme)
}

const loginValidation = (data) => {
    const scheme = {
        username: Joi.string().min(6).required(),
        password: Joi.string().min(6).required()
    };
    return Joi.validate(data, scheme)
}

module.exports.registerValidation = registerValidation
module.exports.loginValidation = loginValidation

