/**
 * Animal Avatar System
 * Using react-icons/gi (Game Icons) for animal representations
 * Only using icons that are confirmed available in react-icons/gi
 */

export interface AnimalAvatar {
  id: string;
  name: string;
  icon: string; // The icon component name
  color: string; // Primary color for the animal
}

export const ANIMAL_AVATARS: AnimalAvatar[] = [
  { id: 'lion', name: 'Lion', icon: 'GiLion', color: '#FFB84D' },
  { id: 'fox', name: 'Fox', icon: 'GiFox', color: '#FF6B35' },
  { id: 'owl', name: 'Owl', icon: 'GiOwl', color: '#9B59B6' },
  { id: 'butterfly', name: 'Butterfly', icon: 'GiButterfly', color: '#E91E63' },
  { id: 'dolphin', name: 'Dolphin', icon: 'GiDolphin', color: '#00D9FF' },
  { id: 'turtle', name: 'Turtle', icon: 'GiTurtle', color: '#27AE60' },
  { id: 'snake', name: 'Snake', icon: 'GiSnake', color: '#8BC34A' },
  { id: 'elephant', name: 'Elephant', icon: 'GiElephant', color: '#95A5A6' },
  { id: 'rabbit', name: 'Rabbit', icon: 'GiRabbit', color: '#ECF0F1' },
  { id: 'bat', name: 'Bat', icon: 'GiBat', color: '#34495E' },
  { id: 'cat', name: 'Cat', icon: 'GiCat', color: '#FF8C94' },
  { id: 'spider', name: 'Spider', icon: 'GiSpiderWeb', color: '#6C3483' },
  { id: 'scorpion', name: 'Scorpion', icon: 'GiScorpion', color: '#E67E22' },
  { id: 'monkey', name: 'Monkey', icon: 'GiMonkey', color: '#D4A574' },
  { id: 'frog', name: 'Frog', icon: 'GiFrog', color: '#4CAF50' },
  { id: 'fish', name: 'Fish', icon: 'GiFishMonster', color: '#3498DB' },
  { id: 'bird', name: 'Bird', icon: 'GiBirdCage', color: '#8B4513' },
  { id: 'mouse', name: 'Mouse', icon: 'GiRat', color: '#A0826D' },
  { id: 'squirrel', name: 'Squirrel', icon: 'GiSquirrel', color: '#D4A574' },
  { id: 'shark', name: 'Shark', icon: 'GiSharkJaws', color: '#2C3E50' },
  { id: 'octopus', name: 'Octopus', icon: 'GiOctopus', color: '#E91E63' },
  { id: 'jellyfish', name: 'Jellyfish', icon: 'GiJellyfish', color: '#9B59B6' },
  { id: 'bee', name: 'Bee', icon: 'GiBee', color: '#FFB84D' },
  { id: 'ladybug', name: 'Ladybug', icon: 'GiLadybug', color: '#FF3864' },
];

/**
 * Get a random animal avatar
 */
export function getRandomAnimal(): AnimalAvatar {
  const randomIndex = Math.floor(Math.random() * ANIMAL_AVATARS.length);
  return ANIMAL_AVATARS[randomIndex];
}

/**
 * Get animal avatar by ID
 */
export function getAnimalById(id: string): AnimalAvatar | undefined {
  return ANIMAL_AVATARS.find(animal => animal.id === id);
}

/**
 * Get animal avatar by icon name
 */
export function getAnimalByIcon(icon: string): AnimalAvatar | undefined {
  return ANIMAL_AVATARS.find(animal => animal.icon === icon);
}
