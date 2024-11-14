## Simple demonstration on how to fuzzer using CuEVM to detect bug

To run the demo in this folder, first you need to install the required packages:
* `pip install -r requirements.txt`
* `apt install libcjson-dev libgmp-dev`


#### Run the fuzzer, use `--help` to check for available options

`python fuzzer.py --input contracts/test_bugs.sol --num_instances 50 --num_iterations 20 --contract_name TestBug  --branch_heuristic`