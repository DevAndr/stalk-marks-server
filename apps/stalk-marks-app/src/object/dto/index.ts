import { Category } from '../types';

export type CreateObjectDto = {
  object: {
    name: string;
    description: string;
  }
  categories: Category[];
};
