// .eslintrc-security.js
module.exports = {
    extends: [
        'plugin:security/recommended',
        'plugin:node/recommended'
    ],
    plugins: [
        'security'
    ],
    rules: {
        'security/detect-object-injection': 'error',
        'security/detect-non-literal-regexp': 'error',
        'security/detect-unsafe-regex': 'error',
        'security/detect-buffer-noassert': 'error',
        'security/detect-eval-with-expression': 'error',
        'security/detect-no-csrf-before-method-override': 'error',
        'security/detect-possible-timing-attacks': 'error',
        'security/detect-pseudoRandomBytes': 'error'
    }
};
