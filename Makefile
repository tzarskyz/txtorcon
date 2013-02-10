.PHONY: test html counts coverage sdist clean install doc
.DEFAULT: test

test:
	trial --reporter=text txtorcon.test

install:
	python setup.py install

doc: docs/*.rst
	cd docs && make html
	cp dist/txtorcon-0.7.tar.gz docs/_build/html
	cp dist/txtorcon-0.6.tar.gz.sig docs/_build/html

coverage:
	trial --reporter=bwverbose --coverage txtorcon
	python scripts/coverage.py

pep8:
	find txtorcon/*.py txtorcon/test/*.py examples/*.py | xargs pep8 --ignore=E501

pep8count:
	find txtorcon/*.py txtorcon/test/*.py examples/*.py | xargs pep8 --ignore=E501 | wc -l

pyflakes:
	pyflakes txtorcon/ examples/

pyflakescount:
	pyflakes txtorcon/ examples/ | wc -l

clean:
	-rm -rf _trial_temp
	-rm -rf build
	-rm -rf dist
	-rm -rf html
	-rm MANIFEST
	-rm `find . -name \*.py[co]`
	-cd docs && make clean

counts:
	ohcount -s txtorcon/*.py

dist: dist/txtorcon-0.7.tar.gz.sig

sdist: setup.py 
	python setup.py sdist

dist/txtorcon-0.7.tar.gz: sdist
dist/txtorcon-0.7.tar.gz.sig: dist/txtorcon-0.7.tar.gz
	gpg --verify dist/txtorcon-0.7.tar.gz.sig || gpg --no-version --detach-sig -u meejah@meejah.ca dist/txtorcon-0.7.tar.gz

release: dist/txtorcon-0.7.tar.gz.sig setup.py
	python setup.py sdist upload

virtualenv:
	mkdir -p tmp
	cd tmp
	virtualenv --never-download --extra-search-dir=/usr/lib/python2.7/dist-packages/ txtorcon_env
	@echo "created tmp/txtorcon_env"
	@echo "see INSTALL for more information"

html: docs/README.rst
	cd docs && make html
