import re
import numpy as np
import matplotlib.pyplot as plt

# ==========================================================
# CONTROLE FINO – AJUSTÁVEL PARA ARTIGO
# ==========================================================

TOTAL_TIME = 60          # segundos
TIME_TICK_STEP = 10       # 0,30,60,...,180

FIG_WIDTH = 24
FIG_HEIGHT = 16
FIG_DPI = 600

LABEL_FONTSIZE = 80
TICK_FONTSIZE = 80
LEGEND_FONTSIZE = 50

AXIS_LINEWIDTH = 10.0
TICK_WIDTH = 20.0
LINE_WIDTH = 10.0

Y_PADDING_RATIO = 0.08    # respiro vertical

LEGEND_LOCATION = "upper right"

# ==========================================================
# CORES PADRÃO (paper-safe)
# ==========================================================

COLOR_L4S = "green"
COLOR_CLASSIC = "blue"
COLOR_MALICIOUS = "red"

# ==========================================================
# PARSER DE ARQUIVO IPERF (robusto)
# ==========================================================

def parse_iperf_file(filepath):
    """
    Parser robusto para saída do iperf:
    - Suporta tempos com várias casas decimais
    - Normaliza throughput para Mbits/sec
    - IGNORA a linha final de SUM / TOTAL
    """

    time_vals = []
    bw_vals = []

    pattern = re.compile(
        r"(\d+\.\d+)\s*-\s*(\d+\.\d+)\s+sec.*?"
        r"([\d\.]+)\s+(bits|Kbits|Mbits|Gbits)/sec"
    )

    with open(filepath, "r") as f:
        for line in f:
            match = pattern.search(line)
            if not match:
                continue

            t_start = float(match.group(1))
            t_end = float(match.group(2))
            bw = float(match.group(3))
            unit = match.group(4)

            # 1️⃣ Ignora linhas agregadas (SUM / TOTAL)
            if (t_end - t_start) > 1.5:
                continue

            # 2️⃣ Normaliza unidade → Mbits/sec
            if unit == "bits":
                bw /= 1e6
            elif unit == "Kbits":
                bw /= 1e3
            elif unit == "Mbits":
                bw = bw
            elif unit == "Gbits":
                bw *= 1e3

            time_vals.append(t_start)
            bw_vals.append(bw)

    return np.array(time_vals), np.array(bw_vals)

# ==========================================================
# AJUSTES FINOS DE EIXOS
# ==========================================================

def configure_axes(ax):
    for spine in ax.spines.values():
        spine.set_linewidth(AXIS_LINEWIDTH)

    ax.tick_params(
        axis="both",
        which="major",
        labelsize=TICK_FONTSIZE,
        width=TICK_WIDTH,
        length=10,
        direction="out"
    )

def configure_time_axis(ax):
    ax.set_xlim(0, TOTAL_TIME)
    ax.set_xticks(np.arange(0, TOTAL_TIME + 1, TIME_TICK_STEP))

def configure_y_padding(ax):
	ax.set_ylim(-1, 120)
	ax.set_yticks(np.arange(0, 120, 20))

# ==========================================================
# CAMINHOS DOS ARQUIVOS
# ==========================================================

FILE_L4S = "baseline_l4s.txt"
FILE_CLASSIC = "baseline_classic.txt"
FILE_MALICIOUS = "baseline_malicious.txt"

# ==========================================================
# LEITURA DOS DADOS
# ==========================================================

t_l4s, bw_l4s = parse_iperf_file(FILE_L4S)
t_classic, bw_classic = parse_iperf_file(FILE_CLASSIC)
t_mal, bw_mal = parse_iperf_file(FILE_MALICIOUS)

# ==========================================================
# PLOT
# ==========================================================

fig, ax = plt.subplots(figsize=(FIG_WIDTH, FIG_HEIGHT))

ax.plot(
    t_l4s,
    bw_l4s,
    label="L4S",
    linewidth=LINE_WIDTH,
    color=COLOR_L4S
)

ax.plot(
    t_classic,
    bw_classic,
    label="Classic I",
    linewidth=LINE_WIDTH,
    color=COLOR_CLASSIC
)

ax.plot(
    t_mal,
    bw_mal,
    label="Classic II",
    linewidth=LINE_WIDTH,
    color=COLOR_MALICIOUS
)

# Labels
ax.set_xlabel("Time (s)", fontsize=LABEL_FONTSIZE, weight="bold")
ax.set_ylabel("Throughput (Mbits/s)", fontsize=LABEL_FONTSIZE, weight="bold")

# Grade sutil
ax.grid(True, linestyle="--", alpha=0.25)

# Legenda
ax.legend(
    loc=LEGEND_LOCATION,
    fontsize=LEGEND_FONTSIZE,
    frameon=True,
    framealpha=0.9
)

# Ajustes finais
configure_axes(ax)
configure_time_axis(ax)
configure_y_padding(ax)

plt.tight_layout()
plt.savefig("throughput_cooperative_scenario1.png", dpi=FIG_DPI, bbox_inches="tight")
plt.close()

print("Gráfico gerado: iperf_throughput_comparison.png")

