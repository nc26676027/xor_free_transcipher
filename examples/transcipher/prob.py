from decimal import Decimal, getcontext, DecimalException
from scipy.special import comb
import math

# Set the desired precision
getcontext().prec = 50

def probability_of_at_least_one_success(h, tilde_K, gamma, N):
    h = Decimal(h)
    tilde_K = Decimal(tilde_K)
    gamma = Decimal(gamma)
    N = Decimal(N)

    # First, calculate the maximum i bound
    max_i = int((tilde_K + gamma * (h + 1)) / (2 * gamma))

    # Initialize the sum
    sum_value = Decimal(0)

    # Calculate the inner sum
    for i in range(max_i + 1):
        term = (tilde_K + gamma * (h + 1)) / (2 * gamma) - i
        
        if term > 0:
            sum_term = ((-1) ** i) * Decimal(comb(int(h + 1), i)) * (term ** (h + 1))
            sum_value += sum_term

    # Factorial part
    factorial_term = Decimal(math.factorial(int(h + 1)))

    # Calculate the power term
    power_term = (1/ factorial_term) * sum_value 

    # Check the value of power_term
    if power_term <= 0:
        print("Calculated power_term is not positive, likely very small or renormalization issues.")
        return Decimal(0), Decimal('-inf')

    try:
        # Use logarithmic computation to avoid overflow
        log_prob_no_success = N * (Decimal(math.log(float(power_term))))
        probability_no_success = Decimal(math.exp(log_prob_no_success))

        # Since the probability can't be greater than 1, we also need to cap it at max
        if probability_no_success > 1:
            probability_no_success = Decimal(1)

        probability_at_least_one_success = 1 - probability_no_success

        if probability_at_least_one_success > 0:
            logprob = Decimal(math.log(float(probability_at_least_one_success)))
        else:
            print("Probability too small to represent.")
            logprob = Decimal('-inf')
    except DecimalException:
        print("Calculated probability value is too small or leads to overflow.")
        probability_at_least_one_success = Decimal(0)
        logprob = Decimal('-inf')

    return probability_at_least_one_success, logprob

# Example parameters
h = 32          # Example value for h
gamma = 3    # Example value for gamma
tilde_K = 50   # Example value for tilde_K
N = 32768        # Number of trials

# Calculate the probability
probability, logprob = probability_of_at_least_one_success(h, tilde_K, gamma, N)
print(f"Probability of succeeding at least once: {probability:.12f}")
print(f"Log Probability of succeeding at least once: {logprob:.12f}")
