=== XSS File Upload Test Suite ===

Images with EXIF XSS:
- xss-comment-*.jpg - XSS in Comment field
- xss-docname.jpg - XSS in DocumentName
- xss-description.jpg - XSS in ImageDescription
- xss-artist.jpg - XSS in Artist field
- xss-console.jpg - XSS with console.log

PNG/GIF:
- xss-png-*.png - PNG with XSS
- xss-gif-*.gif - GIF with XSS

Polyglot Files:
- xss-polyglot.jpg - JPEG/HTML polyglot
- xss-polyglot.svg - SVG polyglot

Advanced:
- xss.svg - SVG with onload
- xss-advanced.svg - SVG with multiple vectors
- xss.html - HTML file
- xss-file.jpg.html - Double extension
- xss-php.jpg - PHP code in image

Usage: Upload these files and check if XSS triggers in:
1. Image display (img src)
2. EXIF metadata display
3. Filename display
4. Download/view functionality
