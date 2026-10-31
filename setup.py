from setuptools import setup, find_packages

setup(
    name="sentinark-trace",
    version="1.0.0",
    author="Shiraz",
    description="Automated Phishing, Redirection Chain & Malicious URL Threat Intelligence Scanner",
    packages=find_packages(),
    install_requires=[
        "Flask>=3.0.0"
    ],
    entry_points={
        "console_scripts": [
            "sentinark-trace=sentinark_trace.cli:main",
            "sentinark-trace-web=sentinark_trace.web_app:run_server"
        ]
    },
    python_requires=">=3.8",
)
