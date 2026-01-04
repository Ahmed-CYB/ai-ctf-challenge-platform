/**
 * Animal Avatar Component
 * Displays an animal icon with consistent styling
 */

import { 
  GiLion, GiFox, GiOwl, GiButterfly,
  GiDolphin, GiTurtle, GiSnake, GiElephant, GiRabbit,
  GiBat, GiCat, GiSpiderWeb,
  GiScorpion, GiMonkey, GiFrog, GiFishMonster,
  GiBirdCage, GiRat, GiSquirrel, GiSharkJaws,
  GiOctopus, GiJellyfish, GiBee, GiLadybug
} from 'react-icons/gi';
import { getAnimalById, getAnimalByIcon, type AnimalAvatar as AnimalAvatarType } from '../utils/animalAvatars';

interface AnimalAvatarProps {
  animalId?: string;
  animalIcon?: string;
  size?: number;
  className?: string;
  showBackground?: boolean;
}

const ICON_MAP: Record<string, any> = {
  GiLion,
  GiFox,
  GiOwl,
  GiButterfly,
  GiDolphin,
  GiTurtle,
  GiSnake,
  GiElephant,
  GiRabbit,
  GiBat,
  GiCat,
  GiSpiderWeb,
  GiScorpion,
  GiMonkey,
  GiFrog,
  GiFishMonster,
  GiBirdCage,
  GiRat,
  GiSquirrel,
  GiSharkJaws,
  GiOctopus,
  GiJellyfish,
  GiBee,
  GiLadybug,
};

export function AnimalAvatar({ 
  animalId, 
  animalIcon, 
  size = 48, 
  className = '',
  showBackground = true 
}: AnimalAvatarProps) {
  // Get animal data
  let animal: AnimalAvatarType | undefined;
  if (animalId) {
    animal = getAnimalById(animalId);
  } else if (animalIcon) {
    animal = getAnimalByIcon(animalIcon);
  }

  // Fallback to lion if not found
  if (!animal) {
    animal = getAnimalById('lion');
  }

  const IconComponent = ICON_MAP[animal!.icon];

  if (!IconComponent) {
    return null;
  }

  if (!showBackground) {
    return (
      <IconComponent 
        size={size} 
        style={{ color: animal!.color }}
        className={className}
      />
    );
  }

  return (
    <div 
      className={`inline-flex items-center justify-center rounded-full ${className}`}
      style={{
        width: size,
        height: size,
        backgroundColor: `${animal!.color}20`,
        border: `2px solid ${animal!.color}40`
      }}
    >
      <IconComponent 
        size={size * 0.6} 
        style={{ color: animal!.color }}
      />
    </div>
  );
}
