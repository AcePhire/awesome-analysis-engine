FROM opensecurity/mobile-security-framework-mobsf:v4.5.3

# tolerate malformed ZIP headers in APKs (see zip_patch/sitecustomize.py).
COPY --chmod=644 --from=zippatch sitecustomize.py /usr/local/lib/python3.13/site-packages/sitecustomize.py
