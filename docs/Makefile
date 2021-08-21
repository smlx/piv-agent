.PHONY: serve
serve:
	cd .. && \
		docker run --rm -it -v $$(pwd):/src -u $$(id -u) -p 1313:1313 \
		--entrypoint sh klakegg/hugo:ext-alpine -c \
		'cd docs && npm install postcss postcss-cli autoprefixer && hugo --baseURL=/ --bind=0.0.0.0 serve'

themes/docsy:
	git clone --recurse-submodules http://github.com/google/docsy themes/docsy
