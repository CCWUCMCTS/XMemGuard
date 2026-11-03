# XMemGuard

Research implementation for Real-Time Detection of Windows Shellcode Injection via the Cross-Process W^X Principle.

Build `XMemGuard.sln` in Release | x64 with Visual Studio 2022, MSVC v143, and the Windows SDK/WDK. Deployment paths are defined in `etw_hook/include/Common.hpp` and `InjectDll/src/Logger.cpp`.

Before deployment, create `C:\XMemGuard\logs`, place the DLL at `C:\XMemGuard\InjectDll.dll`, and ensure target processes have write permission to the log directory.

See [PoC sources and correspondence](docs/POCS.md). The malware hash list is in `data/final_malware_hashes.csv` (1,146 entries).

## Citation

If you use our work or implementation in your research, please consider citing our paper, published in [Cybersecurity](https://doi.org/10.1186/s42400-026-00690-4) on 3 November 2026:

```bibtex
@article{wang2026xmemguard,
  author = {Chengchun Wang and Xing Tian and Xiaoyu Wang and Yuxuan Zhu and Yaqin Cao and Jie Yin and Yuling Liu and Qixu Liu},
  title = {Real-Time Detection of Windows Shellcode Injection via the Cross-Process {W\^{}X} Principle},
  journal = {Cybersecurity},
  volume = {9},
  pages = {250},
  year = {2026},
  doi = {10.1186/s42400-026-00690-4},
  url = {https://doi.org/10.1186/s42400-026-00690-4}
}
```

## Acknowledgments

Thanks to [genIoco](https://github.com/genIoco) and the authors of [FalconEye](https://github.com/rajiv2790/FalconEye), [Starink et al. (2023)](https://github.com/utwente-scs/code-injection-malware), and [Di Pietro et al. (2025)](https://github.com/Sap4Sec/process-injection).
