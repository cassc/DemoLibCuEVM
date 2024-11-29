## Demo on using CuEVM as a library and integrating with fuzzer to detect bug in python 

To run the demo in this folder, first you need to install the required packages:
* `pip install -r requirements.txt`
* `apt install libcjson-dev libgmp-dev`


#### Sample code and run on [🔗 Google Colab link](https://colab.research.google.com/drive/1xPvjpALzXGxCWgvdBs-HiynE0XKytcb4?usp=sharing)
There are two samples: 
1. Running the library wrapper with input state and receive the updated state in python dictionary
2. Running a simpler fuzzer using the library wrapper.

For sample on generating the state input and retrieving the state output, please take a look at `library_wrapper.py`

