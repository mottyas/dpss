#!make

build/wheel:	  ## Сбор дистрибутива пакета
	python setup.py bdist_wheel
