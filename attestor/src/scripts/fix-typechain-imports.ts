/**
 * Post-generation script to fix typechain import extensions
 *
 * Typechain generates files with .js imports, but we run with --experimental-strip-types
 * which requires .ts imports. This script fixes the imports after typechain runs.
 *
 * Usage: npm run run:tsc -- src/scripts/fix-typechain-imports.ts
 */

import fs from 'node:fs'
import path from 'node:path'

const CONTRACTS_DIR = path.join(process.cwd(), 'src/avs/contracts')

function fixImportsInFile(filePath: string): boolean {
	const content = fs.readFileSync(filePath, 'utf8')

	// Replace .js imports with .ts imports for local files
	const fixed = content.replace(
		/from\s+["'](\.[^"']+)\.js["']/g,
		'from "$1.ts"'
	)

	if(fixed !== content) {
		fs.writeFileSync(filePath, fixed)
		return true
	}

	return false
}

function processDirectory(dir: string): number {
	let fixedCount = 0
	const entries = fs.readdirSync(dir, { withFileTypes: true })

	for(const entry of entries) {
		const fullPath = path.join(dir, entry.name)

		if(entry.isDirectory()) {
			fixedCount += processDirectory(fullPath)
		} else if(entry.name.endsWith('.ts')) {
			if(fixImportsInFile(fullPath)) {
				console.log(`Fixed imports in: ${path.relative(process.cwd(), fullPath)}`)
				fixedCount++
			}
		}
	}

	return fixedCount
}

// Main
console.log('Fixing typechain import extensions...')
console.log(`Processing: ${CONTRACTS_DIR}`)

if(!fs.existsSync(CONTRACTS_DIR)) {
	console.error(`Directory not found: ${CONTRACTS_DIR}`)
	process.exit(1)
}

const fixedCount = processDirectory(CONTRACTS_DIR)
console.log(`\nFixed ${fixedCount} file(s)`)
