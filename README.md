# Kyber poly_tomsg attack

This repository contains the artifact related to the: article:
**"Simple Power Analysis assisted Chosen Cipher-Text Attack on ML-KEM"**

> ⚠️ This artifact is only tested for Linux distributions.

-----
## Prerequisites

The following is required:

* Python >= 3
* Pipenv
* Kyber (commit 10b478f)

### Installation Steps
1. Check Python version:  
    ```bash
    python --version # on some systems try python3 --version
    ```
    If not installed or outdated, you can install it with:
    ```bash
    sudo apt-get install python3-full
    ```

2. Check Pip version:  
    ```bash
    pip --version
    ```
    If not installed, use:
    ```bash
    apt install python3-pip
    ```

3. Check Pipenv version:  
    ```bash
    pipenv --version
    ```
    If not installed, run:
    ```bash
    pip install --user pipenv # for debian, add flag --break-system-packages  
    ```  

------
## Recommended Execution Order

### Reproducing the attack without ChipWhisperer

1. Install Virtual Environment Dependencies
    ```bash 
    pipenv sync
    ```

2. Activate the Virtual Environment 
    ```bash 
    pipenv shell
    ```

4. Launch Jupyter Notebook 
    ```bash 
    jupyter notebook
    ```

4. Go to `Attack_without_CW/kyber_polytomsg_leakage_detection.ipynb` and execute the notebook

### Reproducing the attack with ChipWhisperer

1. Install Virtual Environment Dependencies
    ```bash 
    pipenv sync
    ```

2. Activate the Virtual Environment 
    ```bash 
    pipenv shell
    ```

3. Launch Jupyter Notebook 
    ```bash 
    jupyter notebook
    ```

4. Go to the folder `Attack_with_CW/` and choose between
    - `Attack_with_CW/kyber_polytomsg_leakage_detection.ipynb` for the attack on the standard version of $\texttt{poly}\_\texttt{tomsg}$
    - `Attack_with_CW/kyber_polytomsg_leakage_detection_shuffling.ipynb` for the attack on the shuffled version of $\texttt{poly}\_\texttt{tomsg}$

------
## Files
| Name                                         | Description                  |
| :---                                         | :---                         |
| 📁 [Attack_with_CW](./Attack_with_CW/)       | Attack with ChipWhisperer    |
| 📁 [Attack_without_CW](./Attack_without_CW/) | Attack without ChipWhisperer |
| 📁 [Common_functions](./Common_functions/)   | Useful functions used for the attack |
| 📁 [Kyber_CW](./Kyber_CW/)                   | Reference implementation of  [Kyber](https://github.com/pq-crystals/kyber) and [ChipWhisperer](https://github.com/newaetech/chipwhispererfunctions)  functions  |

------
## License

This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).

[![CC BY 4.0](https://i.creativecommons.org/l/by/4.0/88x31.png)](http://creativecommons.org/licenses/by/4.0/)

See [LICENSE.txt](./LICENSE.txt).

This artifact uses the Kyber reference implementation from [GitHub](https://github.com/pq-crystals/kyber), under the Apache 2.0 License, as a submodule.


