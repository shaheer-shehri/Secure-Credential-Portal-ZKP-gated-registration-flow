"""
Script to professionalize the UI by replacing colorful styling with corporate neutral tones.
Replaces all indigo/blue colors with professional grays, blacks, and whites.
"""

import re
import sys
from pathlib import Path

# Define color replacements for professional corporate theme
REPLACEMENTS = [
    # Text colors - dark theme to light theme
    (r'text-white\b', 'text-gray-900'),
    (r'text-slate-100\b', 'text-gray-900'),
    (r'text-slate-200(/\d+)?', r'text-gray-700\1'),
    (r'text-slate-300\b', 'text-gray-600'),
    (r'text-slate-400\b', 'text-gray-500'),
    (r'text-slate-500\b', 'text-gray-400'),
    (r'text-indigo-950', 'text-gray-900'),
    (r'text-indigo-900/80', 'text-gray-700'),
    (r'text-indigo-900/70', 'text-gray-600'),
    (r'text-indigo-700', 'text-gray-700'),
    (r'text-indigo-600', 'text-gray-700'),
    (r'text-indigo-500', 'text-gray-600'),
    (r'text-indigo-400', 'text-gray-500'),
    (r'text-indigo-300', 'text-gray-600'),
    (r'text-indigo-200(/\d+)?', r'text-gray-600\1'),
    (r'text-indigo-100\b', 'text-gray-700'),
    (r'text-blue-600', 'text-gray-700'),
    (r'text-blue-700', 'text-gray-800'),
    (r'text-sky-200', 'text-gray-600'),
    (r'text-sky-300', 'text-gray-600'),
    (r'text-violet-200', 'text-gray-600'),
    (r'text-pink-200', 'text-gray-600'),
    (r'text-amber-200(/\d+)?', r'text-gray-600\1'),
    (r'text-emerald-100', 'text-gray-700'),
    (r'text-emerald-200(/\d+)?', r'text-green-700\1'),
    (r'text-green-200', 'text-green-700'),
    (r'text-rose-200', 'text-red-700'),
    (r'text-rose-300', 'text-red-700'),
    
    # Background colors
    (r'bg-indigo-50', 'bg-gray-50'),
    (r'bg-indigo-100', 'bg-gray-100'),
    (r'bg-blue-50', 'bg-gray-50'),
    (r'bg-blue-100', 'bg-gray-100'),
    (r'bg-blue-600', 'bg-gray-900'),
    (r'bg-blue-700', 'bg-gray-800'),
    (r'bg-slate-900(/\d+)?', r'bg-gray-100\1'),
    (r'bg-slate-950(/\d+)?', r'bg-gray-50\1'),
    
    # Border colors
    (r'border-indigo-100', 'border-gray-200'),
    (r'border-indigo-200', 'border-gray-300'),
    (r'border-indigo-300', 'border-gray-300'),
    (r'border-indigo-400(/\d+)?', r'border-gray-300\1'),
    (r'border-blue-400', 'border-gray-400'),
    (r'border-slate-700', 'border-gray-300'),
    (r'border-white(/\d+)', r'border-gray-300\1'),
    (r'border-sky-400(/\d+)?', r'border-gray-300\1'),
    (r'border-emerald-300(/\d+)?', r'border-green-300\1'),
    (r'border-emerald-400(/\d+)?', r'border-green-400\1'),
    (r'border-emerald-500(/\d+)?', r'border-green-500\1'),
    
    # Ring colors (focus states)
    (r'ring-indigo-300', 'ring-gray-400'),
    (r'ring-indigo-500', 'ring-gray-500'),
    (r'ring-blue-500', 'ring-gray-500'),
    
    # Hover states
    (r'hover:bg-indigo-700', 'hover:bg-gray-800'),
    (r'hover:bg-blue-700', 'hover:bg-gray-800'),
    (r'hover:bg-blue-600', 'hover:bg-gray-700'),
    (r'hover:bg-white(/\d+)', r'hover:bg-gray-50\1'),
    (r'hover:text-white\b', 'hover:text-gray-900'),
    (r'hover:text-blue-600', 'hover:text-gray-900'),
    (r'hover:text-emerald-100', 'hover:text-green-800'),
    (r'hover:bg-emerald-500(/\d+)?', r'hover:bg-green-100\1'),
    (r'hover:bg-indigo-400(/\d+)?', r'hover:bg-gray-200\1'),
    (r'hover:bg-sky-500(/\d+)?', r'hover:bg-gray-100\1'),
    (r'hover:bg-rose-500(/\d+)?', r'hover:bg-red-100\1'),
    (r'hover:underline', 'hover:text-gray-900'),
    
    # Remove rounded-2xl/3xl (too playful), replace with corporate rounded-lg
    (r'rounded-2xl', 'rounded-lg'),
    (r'rounded-3xl', 'rounded-lg'),
    (r'rounded-xl', 'rounded-lg'),
    
    # Tracking letter spacing - reduce playfulness
    (r"tracking-\[0\.4em\]", "tracking-[0.05em]"),
    
    # File input colors
    (r'file:text-indigo-100', 'file:text-gray-700'),
    (r'file:bg-gray-500(/\d+)?', r'file:bg-gray-200\1'),
]

def professionalize_file(filepath):
    """Apply professional styling replacements to a file."""
    try:
        content = filepath.read_text(encoding='utf-8')
        original_content = content
        
        # Apply all replacements
        for pattern, replacement in REPLACEMENTS:
            content = re.sub(pattern, replacement, content)
        
        # Check if any changes were made
        if content != original_content:
            filepath.write_text(content, encoding='utf-8')
            print(f"✓ Updated {filepath.name}")
            return True
        else:
            print(f"  No changes needed for {filepath.name}")
            return False
    except Exception as e:
        print(f"✗ Error processing {filepath}: {e}")
        return False

def main():
    """Process all template files."""
    project_root = Path(__file__).parent.parent
    templates_dir = project_root / 'web_project' / 'templates'
    
    if not templates_dir.exists():
        print(f"Templates directory not found: {templates_dir}")
        sys.exit(1)
    
    print("Professionalizing UI styling...\n")
    
    # Process all HTML files
    html_files = list(templates_dir.rglob('*.html'))
    updated_count = 0
    
    for html_file in html_files:
        if professionalize_file(html_file):
            updated_count += 1
    
    print(f"\n{updated_count}/{len(html_files)} files updated with professional styling.")
    print("Transformation complete!")

if __name__ == '__main__':
    main()
