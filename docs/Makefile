.PHONY: serve
serve:
	cd .. && \
		docker run --rm -it -v $$(pwd):/src -v $$HOME/.cache/hugo_cache:/home/node/.cache/hugo_cache -u $$(id -u) -p 1313:1313 \
		--entrypoint sh hugomods/hugo:latest -c \
		"cd docs && hugo server --baseURL=/ --bind 0.0.0.0"

.PHONY: minify
minify:
	cd .. && \
		docker run --rm -it -v $$(pwd):/src -v $$HOME/.cache/hugo_cache:/home/node/.cache/hugo_cache -u $$(id -u)\
		--entrypoint sh hugomods/hugo:latest -c \
		"cd docs && npm install postcss-cli autoprefixer && hugo --minify"
