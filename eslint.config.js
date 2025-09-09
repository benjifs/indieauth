import { defineConfig } from 'eslint/config'
import globals from 'globals'
import js from '@eslint/js'

export default defineConfig([{
	extends: [ js.configs.recommended ],
	languageOptions: {
		globals: globals.node
	},
	rules: {
		// camelcase: ['error'],
		'comma-dangle': ['error', 'always-multiline'],
		indent: ['error', 'tab'],
		'no-trailing-spaces': 'error',
		semi: ['error', 'never'],
		quotes: ['error', 'single'],
		'guard-for-in': 'error',
	},
}])
