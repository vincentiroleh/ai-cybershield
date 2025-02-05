module.exports = {
    env: {
        node: true,
        es2021: true,
        jest: true,
    },
    extends: [
        'eslint:recommended',
        'prettier', // Make ESLint work nicely with Prettier
    ],
    parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
    },
    rules: {
        // Error prevention
        'no-console': ['warn', { allow: ['warn', 'error'] }],
        'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
        'no-duplicate-imports': 'error',
        'no-var': 'error',

        // Best practices
        'prefer-const': 'error',
        'no-use-before-define': 'error',
        'no-multiple-empty-lines': ['error', { max: 1, maxEOF: 1 }],

        // Style
        'semi': ['error', 'always'],
        'quotes': ['error', 'single'],
        'indent': ['error', 2],
        'comma-dangle': ['error', 'always-multiline'],

        // Error handling
        'no-throw-literal': 'error',
        'handle-callback-err': 'error',

        // Security
        'no-eval': 'error',
        'no-implied-eval': 'error',
        'no-new-func': 'error',
    },
};
