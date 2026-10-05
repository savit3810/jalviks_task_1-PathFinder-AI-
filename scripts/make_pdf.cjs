const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const docsDir = path.join(__dirname, '..', 'docs');
const rawHtmlPath = path.join(docsDir, 'SECURITY_REPORT.html');
const styledHtmlPath = path.join(docsDir, 'SECURITY_REPORT_STYLED.html');
const pdfPath = path.join(docsDir, 'SECURITY_REPORT.pdf');

const bodyContent = fs.readFileSync(rawHtmlPath, 'utf8');

const fullHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Report — PathFinder AI</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    @page {
      size: A4;
      margin: 18mm 16mm 18mm 16mm;
      @bottom-right {
        content: counter(page);
      }
    }

    * {
      box-sizing: border-box;
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      font-size: 10pt;
      line-height: 1.6;
      color: #1f2937;
      background-color: #ffffff;
      padding: 0;
      margin: 0;
    }

    h1, h2, h3, h4, h5, h6 {
      color: #0f172a;
      font-weight: 700;
      page-break-after: avoid;
    }

    h1 {
      font-size: 22pt;
      border-bottom: 2px solid #2563eb;
      padding-bottom: 8px;
      margin-top: 0;
      margin-bottom: 16px;
      color: #1e3a8a;
    }

    h2 {
      font-size: 14pt;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 6px;
      margin-top: 24px;
      margin-bottom: 12px;
      color: #1e40af;
    }

    h3 {
      font-size: 11pt;
      margin-top: 18px;
      margin-bottom: 8px;
      color: #334155;
    }

    p, ul, ol {
      margin-top: 0;
      margin-bottom: 10px;
    }

    li {
      margin-bottom: 4px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0 16px 0;
      font-size: 8.5pt;
      page-break-inside: avoid;
    }

    th, td {
      border: 1px solid #cbd5e1;
      padding: 6px 10px;
      text-align: left;
      vertical-align: top;
    }

    th {
      background-color: #f1f5f9;
      color: #0f172a;
      font-weight: 600;
    }

    tr:nth-child(even) td {
      background-color: #f8fafc;
    }

    code {
      font-family: 'JetBrains Mono', 'Cascadia Code', Consolas, monospace;
      font-size: 8.5pt;
      background-color: #f1f5f9;
      color: #0f172a;
      padding: 2px 5px;
      border-radius: 3px;
      border: 1px solid #e2e8f0;
    }

    pre {
      background-color: #0f172a;
      color: #f8fafc;
      padding: 12px;
      border-radius: 6px;
      overflow-x: auto;
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 8pt;
      line-height: 1.45;
      margin: 10px 0 14px 0;
      page-break-inside: avoid;
    }

    pre code {
      background-color: transparent;
      color: inherit;
      padding: 0;
      border: none;
      font-size: inherit;
    }

    blockquote {
      border-left: 4px solid #3b82f6;
      background-color: #eff6ff;
      margin: 12px 0;
      padding: 8px 14px;
      color: #1e40af;
      page-break-inside: avoid;
    }

    hr {
      border: none;
      border-top: 1px solid #e2e8f0;
      margin: 20px 0;
    }

    .badge {
      display: inline-block;
      padding: 2px 6px;
      font-size: 7.5pt;
      font-weight: 600;
      border-radius: 3px;
      background: #dbeafe;
      color: #1e40af;
    }
  </style>
</head>
<body>
${bodyContent}
</body>
</html>`;

fs.writeFileSync(styledHtmlPath, fullHtml, 'utf8');
console.log('Styled HTML written to:', styledHtmlPath);

const edgePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const fileUrl = 'file:///' + styledHtmlPath.replace(/\\/g, '/');
const command = '"' + edgePath + '" --headless --disable-gpu --run-all-compositor-stages-before-draw --no-pdf-header-footer --print-to-pdf="' + pdfPath + '" "' + fileUrl + '"';

console.log('Running:', command);
execSync(command);
console.log('PDF generated at:', pdfPath);
