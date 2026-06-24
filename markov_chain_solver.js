const STATES = ["N", "H", "C", "R"];

const scenarios = {
  wifi: {
    name: "WiFi",
    distribution: {
      N: 61.55,
      H: 30.25,
      C: 1.92,
      R: 6.28
    }
  },

  cabo: {
    name: "Cabo",
    distribution: {
      N: 34.96,
      H: 33.57,
      C: 11.94,
      R: 19.53
    }
  }
};

const transitionMatrix = [
  // Para:    N     H     C     R
  /* N */ [0.70, 0.25, 0.02, 0.03],
  /* H */ [0.30, 0.45, 0.15, 0.10],
  /* C */ [0.20, 0.35, 0.30, 0.15],
  /* R */ [0.25, 0.35, 0.10, 0.30]
];

const INITIAL_STATE = "N";
const STEPS = 1147;
const RUNS = 1000;

function validateMatrix(matrix) {
  matrix.forEach((row, i) => {
    const sum = row.reduce((acc, value) => acc + value, 0);

    if (Math.abs(sum - 1.0) > 0.000001) {
      throw new Error(`Erro na linha ${STATES[i]}: soma = ${sum}`);
    }
  });
}

function nextState(currentState, matrix) {
  const currentIndex = STATES.indexOf(currentState);
  const probabilities = matrix[currentIndex];
  const random = Math.random();

  let accumulated = 0;

  for (let i = 0; i < probabilities.length; i++) {
    accumulated += probabilities[i];

    if (random <= accumulated) {
      return STATES[i];
    }
  }

  return STATES[STATES.length - 1];
}

function simulateMarkovChain(initialState, steps, matrix) {
  let currentState = initialState;
  const sequence = [currentState];

  for (let i = 1; i < steps; i++) {
    currentState = nextState(currentState, matrix);
    sequence.push(currentState);
  }

  return sequence;
}

function calculateDistribution(sequence) {
  const counts = { N: 0, H: 0, C: 0, R: 0 };

  sequence.forEach(state => {
    counts[state]++;
  });

  const distribution = {};

  for (const state of STATES) {
    distribution[state] = (counts[state] / sequence.length) * 100;
  }

  return {
    counts,
    distribution
  };
}

function runMultipleSimulations(runs, steps, initialState, matrix) {
  const distributions = [];

  for (let i = 0; i < runs; i++) {
    const sequence = simulateMarkovChain(initialState, steps, matrix);
    const result = calculateDistribution(sequence);

    distributions.push(result.distribution);
  }

  return distributions;
}

function calculateAverageDistribution(distributions) {
  const average = {};

  for (const state of STATES) {
    average[state] =
      distributions.reduce((acc, dist) => acc + dist[state], 0) /
      distributions.length;
  }

  return average;
}

function calculateStandardDeviation(distributions, average) {
  const std = {};

  for (const state of STATES) {
    const variance =
      distributions.reduce((acc, dist) => {
        return acc + Math.pow(dist[state] - average[state], 2);
      }, 0) / distributions.length;

    std[state] = Math.sqrt(variance);
  }

  return std;
}

function calculateMeanAbsoluteError(simulated, real) {
  let totalError = 0;

  for (const state of STATES) {
    totalError += Math.abs(simulated[state] - real[state]);
  }

  return totalError / STATES.length;
}

function printResults(average, std, real) {
  console.log("Estado | Média Simulada | Desvio | Real | Erro Absoluto");
  console.log("---------------------------------------------------------");

  for (const state of STATES) {
    const error = Math.abs(average[state] - real[state]);

    console.log(
      `${state.padEnd(6)} | ` +
      `${average[state].toFixed(2).padStart(14)}% | ` +
      `${std[state].toFixed(2).padStart(6)} | ` +
      `${real[state].toFixed(2).padStart(5)}% | ` +
      `${error.toFixed(2).padStart(13)}`
    );
  }

  console.log("---------------------------------------------------------");
  console.log(
    `Erro médio absoluto: ${calculateMeanAbsoluteError(average, real).toFixed(2)} pontos percentuais`
  );
}

validateMatrix(transitionMatrix);

const distributions = runMultipleSimulations(
  RUNS,
  STEPS,
  INITIAL_STATE,
  transitionMatrix
);

const average = calculateAverageDistribution(distributions);
const std = calculateStandardDeviation(distributions, average);

for (const scenario of Object.values(scenarios)) {
  console.log("\n==============================");
  console.log(`CENÁRIO: ${scenario.name}`);
  console.log("==============================\n");

  console.log(`Execuções simuladas: ${RUNS}`);
  console.log(`Amostras por execução: ${STEPS}`);
  console.log(`Estado inicial: ${INITIAL_STATE}\n`);

  printResults(average, std, scenario.distribution);
}