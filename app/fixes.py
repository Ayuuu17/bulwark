"""Copy-paste fix snippets for the most common hosting setups."""

import json


def header_snippets(name: str, value: str) -> dict[str, str]:
    js_name, js_value = json.dumps(name), json.dumps(value)
    vercel = {"headers": [{"source": "/(.*)", "headers": [{"key": name, "value": value}]}]}
    return {
        "Nginx": f'# inside your server {{ }} block\nadd_header {name} "{value}" always;',
        "Apache": f'# .htaccess or <VirtualHost> (needs mod_headers)\nHeader always set {name} "{value}"',
        "Express": (
            "app.use((req, res, next) => {\n"
            f"  res.setHeader({js_name}, {js_value});\n"
            "  next();\n"
            "});"
        ),
        "Next.js": (
            "// next.config.js\n"
            "module.exports = {\n"
            "  async headers() {\n"
            "    return [{\n"
            "      source: '/(.*)',\n"
            f"      headers: [{{ key: {js_name}, value: {js_value} }}],\n"
            "    }];\n"
            "  },\n"
            "};"
        ),
        "Netlify": f"# _headers file in your publish folder\n/*\n  {name}: {value}",
        "Vercel": "// vercel.json\n" + json.dumps(vercel, indent=2),
    }
