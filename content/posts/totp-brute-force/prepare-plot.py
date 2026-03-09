import json
import matplotlib.pyplot as plt
import numpy as np


def probability1(t, R, T: float = 30, N: int = 1_000_000):
    return 1 - np.power(1 - R * T / N, np.floor(t / T))


def probability2(t, R, T: float = 30, N: int = 1_000_000):
    return 1 - np.power(1 - R * T / N, np.floor(t / T)) * (1 - R * np.mod(t, T) / N)


def probability3(t, R, T: float = 30, N: int = 1_000_000):
    return 1 - np.power(1 - R * T / N, t / T)


def dump2d(x, y):
    return json.dumps(np.vstack((x.round(2), y.round(2))).T.tolist())


def dump(x):
    return json.dumps(np.array(x.round(2)).tolist())


h = 8
t = np.linspace(0, 60 * 60 * h, 4 * h + 1)
R = 100

P = probability3(t, R)
x = t / 60
y = 100 * P

print(dump(x))
print(dump(y))

# plt.step(x, y, where="post", color="blue")
# plt.plot(x, y, color="red", ls="--")

plt.plot(x, y, color="red")

plt.xlabel("t [min]")
plt.ylabel("P [%]")
plt.show()
