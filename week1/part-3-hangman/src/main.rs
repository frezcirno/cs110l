// Simple Hangman Program
// User gets five incorrect guesses
// Word chosen randomly from words.txt
// Inspiration from: https://doc.rust-lang.org/book/ch02-00-guessing-game-tutorial.html
// This assignment will introduce you to some fundamental syntax in Rust:
// - variable declaration
// - string manipulation
// - conditional statements
// - loops
// - vectors
// - files
// - user input
// We've tried to limit/hide Rust's quirks since we'll discuss those details
// more in depth in the coming lectures.
extern crate rand;
use rand::Rng;
use std::fs;
use std::io::stdin;
use std::io::stdout;
use std::io::Write;

const NUM_INCORRECT_GUESSES: u32 = 5;
const WORDS_PATH: &str = "words.txt";

fn pick_a_random_word() -> String {
    let file_string = fs::read_to_string(WORDS_PATH).expect("Unable to read file.");
    let words: Vec<&str> = file_string.split('\n').collect();
    String::from(words[rand::thread_rng().gen_range(0, words.len())].trim())
}

fn read_char() -> char {
    let mut letter: char;
    'outer: loop {
        let mut buf = String::new();
        stdin().read_line(&mut buf).unwrap();
        let mut chars = buf.chars();
        loop {
            letter = match chars.next() {
                Some(x) => x,
                _ => break,
            };
            if letter.is_alphabetic() {
                break 'outer;
            }
        }
    }
    letter
}

fn main() {
    let secret_word = pick_a_random_word();
    // Note: given what you know about Rust so far, it's easier to pull characters out of a
    // vector than it is to pull them out of a string. You can get the ith character of
    // secret_word by doing secret_word_chars[i].
    let secret_word_chars: Vec<char> = secret_word.chars().collect();
    // Uncomment for debugging:
    println!("random word: {}", secret_word);

    let len = secret_word.len();
    let mut i = NUM_INCORRECT_GUESSES;
    let mut sofar: Vec<char> = "-".repeat(len).chars().collect();
    let mut guessed = String::new();
    let finish = false;

    println!("Welcome to Guess the Word!");
    while i > 0 && !finish {
        println!("The word so far is {}", sofar.iter().collect::<String>());
        println!("You have guessed the following letters: {}", guessed);
        println!("You have {} guesses left", i);
        print!("Please guess a letter: ");
        stdout().flush().unwrap();
        let letter = read_char();

        let mut progress = false;
        for (i, &sc) in secret_word_chars.iter().enumerate() {
            if sc == letter {
                sofar[i] = letter;
                progress = true;
            }
        }
        if !progress {
            println!("Sorry, that letter is not in the word");
            i -= 1;
        }

        println!();
        guessed.push(letter as char);

        if !sofar.contains(&'-') {
            println!(
                "Congratulations you guessed the secret word: {}!",
                secret_word
            );

            return;
        }
    }

    println!("Sorry, you ran out of guesses!");
    return;
}
